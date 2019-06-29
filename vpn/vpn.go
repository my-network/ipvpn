package vpn

import (
	e "errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/wgcreate"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/xaionaro-go/ipvpn/network"
)

const (
	bufferSize              = 1 << 20
	ipvpnIfaceName          = `ipvpn`
	defaultMTU              = 1200
	ipvpnPort               = 18291
	directConnectionTimeout = 30 * time.Second
)

var (
	ErrAlreadyClosed  = e.New("already closed")
	ErrAlreadyStarted = e.New("already started")
)

type Stream = network.Stream
type AddrInfo = network.AddrInfo

type VPN struct {
	logger           Logger
	myID             peer.ID
	intAlias         IntAlias
	intAliasFilePath string
	peers            sync.Map
	subnet           net.IPNet
	newStreamLocker  sync.Mutex
	buffer           [bufferSize]byte
	wgctl            *wgctrl.Client
	privKey          ed25519.PrivateKey
	psk              []byte
	ifaceName        string
	state            uint32
	currentIP        net.IP
}

func New(intAliasFilePath string, subnet net.IPNet, logger Logger) (vpn *VPN, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err)
			vpn = nil
		}
	}()

	vpn = &VPN{
		logger:           logger,
		subnet:           subnet,
		intAliasFilePath: intAliasFilePath,
		ifaceName:        ipvpnIfaceName,
	}

	vpn.wgctl, err = wgctrl.New()
	if err != nil {
		return
	}

	intAliasFileData, readErr := ioutil.ReadFile(intAliasFilePath)
	if readErr == nil {
		err = vpn.intAlias.Unmarshal(intAliasFileData)
		if err != nil {
			return
		}
		if vpn.intAlias.Timestamp.UnixNano() < time.Date(2019, 06, 23, 19, 47, 29, 0, time.UTC).UnixNano() { // if the computer has a broken battery and the clock shows wrong value
			vpn.intAlias.Timestamp = time.Now()
		}
	} else {
		vpn.intAlias.Value = 1
		vpn.intAlias.Timestamp = time.Now()
		vpn.intAlias.MaxNetworkSize = 1
		err = vpn.UpdateIntAliasMetadataAndSave()
		if err != nil {
			return
		}
	}

	return
}

func (vpn *VPN) GetNetworkMaximalSize() uint64 {
	addressLength := net.IPv6len * 8
	_, bits := vpn.subnet.Mask.Size()
	if vpn.subnet.IP.To4() != nil {
		addressLength = net.IPv4len * 8
	}
	return (1 << uint(addressLength-bits)) - 3
}

func (vpn *VPN) SetID(newID peer.ID) {
	vpn.myID = newID
	vpn.intAlias.PeerID = vpn.myID
	err := vpn.UpdateIntAliasMetadataAndSave()
	if err != nil {
		vpn.logger.Error(errors.Wrap(err))
	}
}

func (vpn *VPN) setPrivateKey(privKey ed25519.PrivateKey) {
	vpn.privKey = privKey
}

func (vpn *VPN) GetIP(intAlias uint64) (net.IP, error) {
	maskOnes, maskBits := vpn.subnet.Mask.Size()
	if vpn.intAlias.Value >= 1<<uint32(maskBits-maskOnes) {
		return nil, errors.New("int alias value is too big or subnet is too small")
	}

	resultIP := make(net.IP, len(vpn.subnet.IP))
	copy(resultIP, vpn.subnet.IP)
	if resultIP.To4() == nil {
		return nil, errors.New("IPv6 support is not implemented, yet")
	}

	if uint64(resultIP[len(resultIP)-1])+intAlias >= 255 {
		return nil, errors.New("are not implemented, yet; we can only modify the last octet at the moment of an IP address")
	}
	resultIP[len(resultIP)-1] += uint8(intAlias)
	return resultIP, nil
}

func (vpn *VPN) GetMyIP() (net.IP, error) {
	return vpn.GetIP(vpn.intAlias.Value)
}

func (vpn *VPN) getPeers() (peers Peers) {
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		peers = append(peers, peer)
		return true
	})

	return
}

func (vpn *VPN) IsStarted() bool {
	return atomic.LoadUint32(&vpn.state) == 1
}

func (vpn *VPN) Start() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !atomic.CompareAndSwapUint32(&vpn.state, 0, 1) {
		return ErrAlreadyStarted
	}

	vpn.ifaceName, err = wgcreate.Create(vpn.ifaceName, defaultMTU, true, &device.Logger{
		Debug: log.New(vpn.logger.GetDebugWriter(), "[wireguard] ", 0),
		Info:  log.New(vpn.logger.GetInfoWriter(), "[wireguard] ", 0),
		Error: log.New(vpn.logger.GetErrorWriter(), "[wireguard] ", 0),
	})
	if err != nil {
		return
	}

	err = vpn.updateWireGuardConfiguration()
	if err != nil {
		_ = vpn.deleteLink()
		return
	}

	err = vpn.startFallbackConnector()
	if err != nil {
		_ = vpn.deleteLink()
		return
	}

	return
}

func (vpn *VPN) switchToFallback(peer *Peer) {

}

func (vpn *VPN) fallbackConnectorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	for vpn.IsStarted() {
		select {
		case <-ticker.C:
		}

		for _, vpnPeer := range vpn.getPeers() {
			var err error
			if time.Since(vpnPeer.WgDirect.LastHandshakeTime).Nanoseconds() < directConnectionTimeout.Nanoseconds() {
				err = vpnPeer.switchChannel(channelTypeDirect)
			} else {
				err = vpnPeer.switchChannel(channelTypeIPFS)
			}
			if err != nil {
				vpn.logger.Error(errors.Wrap(err))
			}
		}
	}
}

func (vpn *VPN) startFallbackConnector() (err error) {
	defer func() { err = errors.Wrap(err) }()

	go vpn.fallbackConnectorLoop()

	return
}

func (vpn *VPN) deleteLink() (err error) {
	defer func() { err = errors.Wrap(err) }()

	// TODO: implement it

	return
}

func (vpn *VPN) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !atomic.CompareAndSwapUint32(&vpn.state, 1, 0) {
		return ErrAlreadyClosed
	}

	err = vpn.wgctl.Close()
	if err != nil {
		return
	}

	err = vpn.deleteLink()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) updateWireGuardConfiguration() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !vpn.IsStarted() {
		return
	}

	peersCfg, err := vpn.getPeers().toWireGuardConfigs()
	if err != nil {
		return
	}

	cfg := wgtypes.Config{
		PrivateKey:   &wgtypes.Key{},
		ListenPort:   &[]int{ipvpnPort}[0],
		FirewallMark: &[]int{1}[0],
		Peers:        peersCfg,
		ReplacePeers: true,
	}

	copy(cfg.PrivateKey[:], vpn.privKey)

	err = vpn.wgctl.ConfigureDevice(vpn.ifaceName, cfg)
	if err != nil {
		return
	}

	err = vpn.setupIfaceIPAddress()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) SetPrivateKey(privKey ed25519.PrivateKey) {
	vpn.setPrivateKey(privKey)
	err := vpn.updateWireGuardConfiguration()
	if err != nil {
		vpn.logger.Error("unable to configure VPN", err)
	}
}

func (vpn *VPN) setPSK(psk []byte) {
	vpn.psk = psk
}

func (vpn *VPN) SetPSK(psk []byte) {
	vpn.setPSK(psk)
	err := vpn.updateWireGuardConfiguration()
	if err != nil {
		vpn.logger.Error("unable to configure VPN", err)
	}
}

func (vpn *VPN) GetPSK() []byte {
	return vpn.psk
}

func (vpn *VPN) sendIntAliases(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	knownAliases := IntAliases{vpn.intAlias.Copy()}
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		knownAliases = append(knownAliases, peer.IntAlias.Copy())
		return true
	})
	for _, intAlias := range knownAliases {
		intAlias.Since = time.Since(intAlias.Timestamp)
		intAlias.Timestamp = time.Time{}
	}
	b, err := knownAliases.Marshal()
	if err != nil {
		return
	}

	n, err := stream.Write(b)
	vpn.logger.Debugf("sendIntAlias(): stream.Write(): %v %v %v", n, err, string(b))
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) recvIntAliases(stream Stream) (remoteIntAliases IntAliases, err error) {
	defer func() { err = errors.Wrap(err) }()

	n, err := stream.Read(vpn.buffer[:])
	vpn.logger.Debugf("recvIntAlias(): stream.Read(): %v %v %v", n, err, string(vpn.buffer[:n]))

	if n >= bufferSize {
		return nil, errors.New("too big message")
	}
	if err != nil {
		return
	}

	err = remoteIntAliases.Unmarshal(vpn.buffer[:n])
	if err != nil {
		return
	}

	if len(remoteIntAliases) == 0 {
		return nil, errors.New("empty slice")
	}

	return
}

func (vpn *VPN) setupIfaceIPAddress() (err error) {
	defer func() { err = errors.Wrap(err) }()

	myIP, err := vpn.GetMyIP()
	if err != nil {
		return
	}

	if vpn.currentIP.String() == myIP.String() {
		return
	}

	vpn.currentIP = myIP

	err = wgcreate.ResetIPs(vpn.ifaceName)
	if err != nil {
		return
	}

	err = wgcreate.AddIP(vpn.ifaceName, myIP, vpn.subnet)
	if err != nil {
		return
	}

	return nil
}

func (vpn *VPN) SetIntAlias(newValue uint64) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("SetIntAlias: %v->%v", vpn.intAlias.Value, newValue)

	vpn.intAlias.Value = newValue
	vpn.intAlias.Timestamp = time.Now()

	return vpn.setupIfaceIPAddress()
}

func (vpn *VPN) GetNetworkSize() (result uint64) {
	result = 1 // myself is already "1"

	vpn.peers.Range(func(_, _ interface{}) bool {
		result++
		return true
	})

	return
}

func (vpn *VPN) UpdateIntAliasMetadataAndSave() (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("saving the int alias %v to %v", vpn.intAlias, vpn.intAliasFilePath)

	curNetworkSize := vpn.GetNetworkSize()
	if curNetworkSize > vpn.intAlias.MaxNetworkSize {
		vpn.intAlias.MaxNetworkSize = curNetworkSize
	}
	vpn.intAlias.Timestamp = time.Now()
	b, err := vpn.intAlias.Marshal()
	if err != nil {
		return
	}

	err = ioutil.WriteFile(vpn.intAliasFilePath+"-new", b, 0644)
	if err != nil {
		return
	}

	_ = os.Remove(vpn.intAliasFilePath)

	err = os.Rename(vpn.intAliasFilePath+"-new", vpn.intAliasFilePath)
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) newStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.newStreamLocker.Lock()
	defer vpn.newStreamLocker.Unlock()

	peerID := stream.Conn().RemotePeer()
	if peerID == vpn.myID {
		return errors.New("got a connection to myself, should not happened, ever")
	}
	err = vpn.sendIntAliases(stream)
	if err != nil {
		return
	}
	remoteIntAliases, err := vpn.recvIntAliases(stream)
	if err != nil {
		return
	}
	notMyIntAliases := map[uint64]*IntAlias{}
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		notMyIntAliases[peer.IntAlias.Value] = &peer.IntAlias
		return true
	})
	for _, remoteIntAlias := range remoteIntAliases {
		if remoteIntAlias.PeerID == vpn.intAlias.PeerID {
			continue
		}
		remoteIntAlias.Timestamp = time.Now().Add(-remoteIntAlias.Since)
		notMyIntAliases[remoteIntAlias.Value] = remoteIntAlias
	}
	if remoteIntAliases[0].Value == vpn.intAlias.Value {
		changeOnRemoteSide := false
		if vpn.intAlias.MaxNetworkSize > remoteIntAliases[0].MaxNetworkSize {
			changeOnRemoteSide = true
		} else if vpn.intAlias.MaxNetworkSize == remoteIntAliases[0].MaxNetworkSize {
			if vpn.intAlias.Timestamp.UnixNano() > remoteIntAliases[0].Timestamp.UnixNano() {
				changeOnRemoteSide = true
			} else if vpn.intAlias.Timestamp.UnixNano() == remoteIntAliases[0].Timestamp.UnixNano() {
				if vpn.myID < peerID {
					changeOnRemoteSide = true
				}
			}
		}

		if changeOnRemoteSide {
			vpn.logger.Debugf("int alias collision, remote side should change it's alias %v <?= %v , %v <?= %v, %v >? %v",
				vpn.intAlias.Value, remoteIntAliases[0].Value,
				vpn.intAlias.Timestamp, remoteIntAliases[0].Timestamp,
				vpn.myID, peerID)

			err = vpn.sendIntAliases(stream)
			if err != nil {
				return
			}
			remoteIntAliases, err = vpn.recvIntAliases(stream)
			if err != nil {
				return
			}
			if remoteIntAliases[0].Value == vpn.intAlias.Value {
				return errors.New("remote side decided not to change it's int alias, close connection")
			}
		} else {
			vpn.logger.Debugf("int alias collision, changing our int alias")
			networkSize := vpn.GetNetworkMaximalSize()
			for i := uint64(1); i < networkSize; i++ {
				if notMyIntAliases[i] == nil {
					err = vpn.SetIntAlias(i)
					if err != nil {
						return
					}
					break
				}
			}
			err = vpn.sendIntAliases(stream)
			if err != nil {
				return
			}
			_, err = vpn.recvIntAliases(stream)
			if err != nil {
				return
			}
		}
	}

	if oldPeerI, _ := vpn.peers.Load(peerID); oldPeerI != nil {
		oldPeer := oldPeerI.(*Peer)
		_ = oldPeer.Close()
	}

	remoteIntAliases[0].Timestamp = time.Now().Add(-remoteIntAliases[0].Since)
	newPeer := &Peer{
		VPN:      vpn,
		Stream:   stream,
		AddrInfo: peerAddr,
		IntAlias: *remoteIntAliases[0],
	}

	err = newPeer.Start()
	if err != nil {
		return
	}

	vpn.peers.Store(peerID, newPeer)

	saveErr := vpn.UpdateIntAliasMetadataAndSave()
	if saveErr != nil {
		vpn.logger.Error(saveErr)
	}

	return
}

func (vpn *VPN) NewStream(stream Stream, peerAddr AddrInfo) {
	if err := vpn.newStream(stream, peerAddr); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		_ = stream.Close()
	}
}
