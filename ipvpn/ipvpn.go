package ipvpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"

	"github.com/denisbrodbeck/machineid"
	"github.com/sirupsen/logrus"

	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/pinentry"

	"github.com/my-network/ipvpn/config"
	"github.com/my-network/ipvpn/helpers"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/ipvpn/router"
	"github.com/my-network/ipvpn/vpn"
)

const (
	MachineIDLength = 8
)

func errorIf(err error) {
	if err != nil {
		logrus.Error(err)
	}
}

type debugLogger struct{}

func (l *debugLogger) Printf(fmt string, args ...interface{}) {
	logrus.Debugf(fmt, args...)
}

func (l *debugLogger) Print(args ...interface{}) {
	logrus.Debug(args...)
}

func readFromFile(dir, file string) ([]byte, error) {
	filePath := filepath.Join(dir, file)
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read file", filePath)
	}
	return b, nil
}

func readStringFromFileTrim(dir, file string) (string, error) {
	b, err := readFromFile(dir, file)
	return strings.Trim(string(b), " \t\n\r"), errors.Wrap(err)
}

func readFromFileUnhex(dir, file string) ([]byte, error) {
	b, err := readFromFile(dir, file)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	hexed := strings.Trim(string(b), " \t\n\r")
	data, err := hex.DecodeString(hexed)
	return data, errors.Wrap(err)
}

func toSize(in []byte, length uint) []byte {
	result := make([]byte, length)
	copy(result, in)
	return result
}

func encryptHex(block cipher.Block, dataIn []byte) (string, error) {
	paddedLength := (len(dataIn) + aes.BlockSize - 1) & 0xfff0
	data := make([]byte, paddedLength)
	copy(data, dataIn)
	var out bytes.Buffer

	err := binary.Write(&out, binary.LittleEndian, uint32(len(dataIn)))
	if err != nil {
		return "", errors.Wrap(err)
	}

	err = binary.Write(&out, binary.LittleEndian, uint32(crc32.ChecksumIEEE(data)))
	if err != nil {
		return "", errors.Wrap(err)
	}

	out.Write(make([]byte, aes.BlockSize-4-4))

	out.Write(data)
	decrypted := out.Bytes()

	encrypted := make([]byte, len(decrypted))
	for i := 0; i < len(decrypted); i += aes.BlockSize {
		block.Encrypt(encrypted[i:i+aes.BlockSize], decrypted[i:i+aes.BlockSize])
	}

	return hex.EncodeToString(encrypted), nil
}

func unhexDecrypt(block cipher.Block, dataString string) ([]byte, error) {
	if len(dataString) < 8 {
		return nil, errors.New("data too small")
	}

	encrypted, err := hex.DecodeString(strings.Trim(dataString, " \t\r\n"))
	if err != nil {
		return nil, errors.Wrap(err)
	}

	decrypted := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], encrypted[i:i+aes.BlockSize])
	}

	in := bytes.NewReader(decrypted)

	var length uint32
	err = binary.Read(in, binary.LittleEndian, &length)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	var checksum uint32
	err = binary.Read(in, binary.LittleEndian, &checksum)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	_, _ = in.Read(make([]byte, aes.BlockSize-4-4))

	checksumCompare := crc32.ChecksumIEEE(decrypted[aes.BlockSize:])
	if checksum != checksumCompare {
		return nil, errors.New("unable to decrypt (checksum did not match)", checksum, checksumCompare)
	}

	if int(length) > len(decrypted[aes.BlockSize:]) {
		return nil, errors.New("invalid length", int(length), len(decrypted[aes.BlockSize:]))
	}

	return decrypted[aes.BlockSize : aes.BlockSize+length], nil
}

func writeStringToFile(dir, path, data string, perms os.FileMode) error {
	filePath := filepath.Join(dir, path)

	_ = os.Remove(filePath)

	file, err := os.Create(filePath)
	if err != nil {
		return errors.Wrap(err, "unable to create the file", filePath)
	}
	if err = file.Chmod(perms); err != nil {
		return errors.Wrap(err, "unable to set permissions on file", filePath)
	}
	if _, err = file.WriteString(data + "\n"); err != nil {
		return errors.Wrap(err, "unable to write to file", filePath)
	}
	return nil
}

func savePassword(dataDir string, newPassword []byte, cipher cipher.Block) error {
	// This application is aimed on goofy computer users, so we encrypt the password
	// just to protect it from being _accidentally_ transferred to third parties (like
	// giving a not-wiped-up flash drive to a friend)
	passwordEncryptedHex, err := encryptHex(cipher, newPassword)
	if err != nil {
		return errors.Wrap(err, "unable to encrypt&encode the password")
	}

	err = writeStringToFile(dataDir, "password.encrypted-hex", passwordEncryptedHex, 0400)
	if err != nil {
		return errors.Wrap(err, `unable to write the password to the file`)
	}

	return nil
}

type IPVPN struct {
	Network *network.Network
	VPN     *vpn.VPN
	Router  *router.Router
}

func NewIPVPN() (ipvpn *IPVPN, err error) {
	defer func() { err = errors.Wrap(err) }()
	ipvpn = &IPVPN{}

	if addr := config.Get().PprofNetAddress; addr != "" {
		go func() {
			logrus.Error(http.ListenAndServe(addr, nil))
		}()
	}

	dataDir := config.Get().DataDirectory

	logrus.SetLevel(logrus.DebugLevel)

	hostname, _ := os.Hostname()
	machineID, _ := machineid.ProtectedID("ipvpn")
	if len(machineID) > MachineIDLength {
		machineID = machineID[:MachineIDLength]
	}
	peerName := hostname + "_" + machineID
	if peerName == "_" {
		peerName = ""
	}

	if config.Get().DumpConfiguration {
		logrus.Debugf("Configuration == %v", config.Get())
	}

	if err := os.MkdirAll(dataDir, 0750); err != nil {
		logrus.Error(errors.Wrap(err))
	}

	networkID, err := readStringFromFileTrim(dataDir, "network_id.txt")
	if err != nil && os.IsNotExist(err.(*errors.Error).Deepest().Err) {
		var pinentryClient pinentry.PinentryClient
		pinentryClient, err = pinentry.NewPinentryClient()
		if err != nil {
			return
		}

		pinentryClient.SetTitle(`MyNet credentials`)
		pinentryClient.SetPrompt(`My network name`)
		pinentryClient.SetCancel(`Exit`)
		pinentryClient.SetOK(`Next`)

		var networkIDBytes []byte
		networkIDBytes, err = pinentryClient.GetPin()
		if err != nil {
			return
		}
		pinentryClient.Close()

		networkID = string(networkIDBytes)
		err = writeStringToFile(dataDir, "network_id.txt", networkID, 0400)
	}

	if err != nil {
		return
	}

	cipher, err := aes.NewCipher(toSize([]byte(peerName), aes.BlockSize*2))
	if err != nil {
		return
	}

	passwordSourceFile := "password_new.txt"
	passwordString, err := readStringFromFileTrim(dataDir, "password_new.txt")
	password := []byte(passwordString)
	if err != nil && os.IsNotExist(err.(*errors.Error).Deepest().Err) {
		passwordSourceFile = "password_new.hex"
		password, err = readFromFileUnhex(dataDir, "password_new.hex")
	}
	switch {
	case err == nil:
		err = savePassword(dataDir, password, cipher)
		if err != nil {
			return
		}

		_ = os.Remove(filepath.Join(dataDir, passwordSourceFile))
	case err != nil && os.IsNotExist(err.(*errors.Error).Deepest().Err):
		var passwordEncryptedHex string
		passwordEncryptedHex, err = readStringFromFileTrim(dataDir, "password.encrypted-hex")
		switch {
		case err == nil:
			password, err = unhexDecrypt(cipher, passwordEncryptedHex)
			if err != nil {
				err = errors.Wrap(err, "unable to decode&decrypt the password")
				return
			}
		case err != nil && os.IsNotExist(err.(*errors.Error).Deepest().Err):
			var pinentryClient pinentry.PinentryClient
			pinentryClient, err = pinentry.NewPinentryClient()
			if err != nil {
				return
			}

			pinentryClient.SetTitle(`MyNet credentials`)
			pinentryClient.SetPrompt(`Password`)
			pinentryClient.SetCancel(`Exit`)
			pinentryClient.SetOK(`Enter`)
			password, err = pinentryClient.GetPin()
			if err != nil {
				return
			}
			pinentryClient.Close()

			err = savePassword(dataDir, password, cipher)
			if err != nil {
				return
			}
		default:
			if err != nil {
				return
			}
		}

	default:
		if err != nil {
			return
		}
	}

	passwordHash := helpers.Hash([]byte(password))

	_, subnet, err := net.ParseCIDR(config.Get().NetworkSubnet)
	if err != nil {
		return
	}

	vpnLogger := &logger{"[vpn]", true, config.Get().DumpVPNCommunications}

	ipvpn.VPN, err = vpn.New(filepath.Join(dataDir, "vpn"), *subnet, vpnLogger)
	if err != nil {
		return
	}

	netLogger := &logger{"[net]", true, config.Get().DumpNetworkCommunications}

	agreeToBeRelay := false

	routerLogger := &logger{"[router]", true, config.Get().DumpNetworkCommunications}
	ipvpn.Router = router.New(routerLogger)

	err = network.FixOSSettings()
	if err != nil {
		return
	}

	ipvpn.Network, err = network.New(networkID, passwordHash, filepath.Join(dataDir, "network"), agreeToBeRelay, netLogger, ipvpn.VPN, ipvpn.Router)
	if err != nil {
		return
	}

	ipvpn.VPN.AddUpperHandler(ipvpn.Router)

	return
}

func (ipvpn *IPVPN) Close() error {
	_ = ipvpn.Router.Close()
	_ = ipvpn.VPN.Close()
	_ = ipvpn.Network.Close()

	return nil
}
