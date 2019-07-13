package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	e "errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/agl/ed25519/extra25519"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/wgcreate"
	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	bufferSize                  = 1 << 20
	ipvpnIfaceNamePrefix        = `ipvpn_`
	defaultMTU                  = 1280
	ipvpnWGPortDirect           = 18291
	ipvpnWGPortIPFS             = 18292
	ipvpnWGPortSimpleTunnel     = 18293
	ipvpnTunnelPortSimpleTunnel = 18294
	directConnectionTimeout     = 30 * time.Second
)

var (
	secondaryKeyBase = [32]byte{'i', 'p', 'v', 'p', 'n'}
)

var (
	ErrAlreadyClosed  = e.New("already closed")
	ErrAlreadyStarted = e.New("already started")
)

type Stream = network.Stream
type AddrInfo = network.AddrInfo

type VPN struct {
	logger                             Logger
	myID                               peer.ID
	ifaceNamePrefix                    string
	intAlias                           IntAlias
	intAliasFilePath                   string
	peers                              sync.Map
	newStreamLocker                    sync.Mutex
	buffer                             [bufferSize]byte
	privKey                            ed25519.PrivateKey
	psk                                []byte
	state                              uint32
	wgctl                              *wgctrl.Client
	wgnets                             [channelType_max]WGNet
	directConnectorTrigger             chan struct{}
	simpleTunnelListener               *net.UDPConn
	simpleTunnelExternalListener       *net.UDPConn
	simpleTunnelExternalListenerLocker sync.RWMutex
	simpleTunnelReaderMap              atomicmap.Map
	myExternalPort                     uint16

	pingSenderLoopCancelFunc atomicmap.Map
}

func New(intAliasFilePath string, subnet net.IPNet, logger Logger) (vpn *VPN, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err)
			vpn = nil
		}
	}()

	vpn = &VPN{
		logger:                 logger,
		intAliasFilePath:       intAliasFilePath,
		ifaceNamePrefix:        ipvpnIfaceNamePrefix,
		directConnectorTrigger: make(chan struct{}, 256),

		simpleTunnelReaderMap:    atomicmap.New(),
		pingSenderLoopCancelFunc: atomicmap.New(),
	}

	// Splitting "subnet" to 4 subnets: direct, ipfs, simpleTunnel, autoRouted
	{
		maskOnes, maskBits := subnet.Mask.Size()
		maskOnes += 2 // Splitting the subnet to 4, so in each mask amount of one's is increased to 2
		newMask := net.CIDRMask(maskOnes, maskBits)
		for idx, chType := range channelTypes {
			wgnet := &vpn.wgnets[chType]
			wgnet.Subnet.IP, err = getIPByOffset(subnet.IP, uint64(idx)*1<<uint(maskBits-maskOnes))
			wgnet.Subnet.Mask = newMask
		}
	}

	vpn.wgctl, err = wgctrl.New()
	if err != nil {
		return
	}

	// Load intAlias
	{
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
	}

	return
}

func (vpn *VPN) GetNetworkMaximalSize() uint64 {
	addressLength := net.IPv6len * 8
	subnet := vpn.wgnets[channelTypeDirect].Subnet
	_, bits := subnet.Mask.Size()
	if subnet.IP.To4() != nil {
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

func getIPByOffset(subnetIP net.IP, offset uint64) (resultIP net.IP, err error) {
	defer func() { err = errors.Wrap(err) }()

	resultIP = make(net.IP, len(subnetIP))
	copy(resultIP, subnetIP)
	if resultIP.To4() == nil {
		return nil, errors.New("IPv6 support is not implemented, yet")
	}

	octet := len(resultIP) - 1

	for offset > 0 && octet >= 0 {
		localOffset := uint8(offset % 256)
		offset /= 256
		if uint16(resultIP[octet])+uint16(localOffset) >= 256 {
			offset++
		}
		resultIP[octet] += localOffset
		octet--
	}

	return
}

func (vpn *VPN) GetIP(intAlias uint64, chType channelType) (resultIP net.IP, err error) {
	defer func() { err = errors.Wrap(err) }()
	defer func() { vpn.logger.Debugf("GetIP(%v, %v) -> %v, %v", intAlias, chType, resultIP, err) }()

	subnet := vpn.wgnets[chType].Subnet

	maskOnes, maskBits := subnet.Mask.Size()
	if vpn.intAlias.Value >= 1<<uint32(maskBits-maskOnes) {
		return nil, errors.New("int alias value is too big or subnet is too small")
	}

	return getIPByOffset(subnet.IP, intAlias)
}

func (vpn *VPN) subnetContainsMultiaddr(maddr multiaddr.Multiaddr, chType channelType) bool {
	addr4, err := maddr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return false
	}
	subnet := vpn.wgnets[chType].Subnet
	return subnet.Contains(net.ParseIP(addr4))
}

func (vpn *VPN) IsBadAddress(maddr multiaddr.Multiaddr) bool {
	return vpn.subnetContainsMultiaddr(maddr, channelTypeIPFS)
}

func (vpn *VPN) GetMyIP(chType channelType) (net.IP, error) {
	return vpn.GetIP(vpn.intAlias.Value, chType)
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

	for _, chType := range channelTypes {
		vpn.wgnets[chType].IfaceName, err = wgcreate.Create(vpn.ifaceNamePrefix+chType.String(), defaultMTU, true, &device.Logger{
			Debug: log.New(vpn.logger.GetDebugWriter(), "[wireguard-"+chType.String()+"] ", 0),
			Info:  log.New(vpn.logger.GetInfoWriter(), "[wireguard-"+chType.String()+"] ", 0),
			Error: log.New(vpn.logger.GetErrorWriter(), "[wireguard-"+chType.String()+"] ", 0),
		})
		if err != nil {
			return
		}
	}

	err = vpn.updateWireGuardConfiguration()
	if err != nil {
		_ = vpn.deleteLinks()
		return
	}

	err = vpn.startDirectConnector()
	if err != nil {
		_ = vpn.deleteLinks()
		return
	}

	var simpleTunnelListener *net.UDPConn
	simpleTunnelListener, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: ipvpnTunnelPortSimpleTunnel,
	})
	if err != nil {
		return
	}
	vpn.simpleTunnelListener = simpleTunnelListener
	go vpn.simpleTunnelListenerReader(simpleTunnelListener)

	vpn.simpleTunnelExternalListenerLocker.Lock()
	defer vpn.simpleTunnelExternalListenerLocker.Unlock()

	if vpn.myExternalPort > 0 {
		err = vpn.restartSimpleTunnelExternalListener(vpn.myExternalPort)
		if err != nil {
			return
		}
	}

	return
}

func (vpn *VPN) considerMyExternalPort(port uint16) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("considerMyExternalPort(%v)", port)

	vpn.simpleTunnelExternalListenerLocker.Lock()
	defer vpn.simpleTunnelExternalListenerLocker.Unlock()

	if port == vpn.myExternalPort {
		return
	}

	if !vpn.IsStarted() {
		vpn.myExternalPort = port
		return
	}

	return vpn.restartSimpleTunnelExternalListener(port)
}

func (vpn *VPN) restartSimpleTunnelExternalListener(port uint16) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("restartSimpleTunnelExternalListener(%v)", port)

	if vpn.simpleTunnelExternalListener != nil {
		_ = vpn.simpleTunnelExternalListener.Close()
	}

	if port == 0 {
		vpn.myExternalPort = 0
		return nil
	}

	var simpleTunnelExternalListener *net.UDPConn
	simpleTunnelExternalListener, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: int(port),
	})
	if err != nil {
		return
	}
	vpn.simpleTunnelExternalListener = simpleTunnelExternalListener
	go vpn.simpleTunnelListenerReader(simpleTunnelExternalListener)

	vpn.myExternalPort = port

	return
}

func (vpn *VPN) SetMyAddrs(addrs []multiaddr.Multiaddr) {
	// Find usual IPFS TCP port
	var ipfsPort uint16
	for _, addr := range addrs {
		ipStr, err := addr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			//vpn.logger.Error(errors.Wrap(err, `unable to extract IP from address`, addr))
			continue
		}
		ip := net.ParseIP(ipStr)
		if !ip.IsLoopback() {
			continue
		}

		portStr, err := addr.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err, `unable to extract TCP port from address`, addr))
			break
		}
		port, err := strconv.ParseInt(portStr, 10, 64)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err, `unable to parse port from address`, addr))
			break
		}
		ipfsPort = uint16(port)
		break
	}

	if ipfsPort == 0 {
		vpn.logger.Error("I did not find a loopback interface in the addresses list, so I don't know my usual port for IPFS :(")
		return
	}

	for _, addr := range addrs {
		portStr, err := addr.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			//vpn.logger.Debugf(`unable to extract TCP port from address %v: %v`, addr, err)
			continue
		}
		port, err := strconv.ParseInt(portStr, 10, 64)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err, `unable to parse port from address`, addr))
			continue
		}
		if uint16(port) == ipfsPort {
			continue
		}

		err = vpn.considerMyExternalPort(uint16(port) + 1)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			continue
		}
		break
	}
}

const simpleTunnelListenerReaderCacheSize = 0

func (vpn *VPN) simpleTunnelListenerReader(conn *net.UDPConn) {
	vpn.logger.Debugf("started simpleTunnelListenerReader(%v)", conn.LocalAddr())
	defer vpn.logger.Debugf("finished simpleTunnelListenerReader(%v)", conn.LocalAddr())

	cache := make([]*simpleTunnelReader, 0, simpleTunnelListenerReaderCacheSize)

	addrBuf := make([]byte, 2+net.IPv6len)
	buf := make([]byte, bufferSize)
	for vpn.IsStarted() {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				vpn.logger.Error(errors.Wrap(err, fmt.Sprintf("%T", err), fmt.Sprintf("%T", netErr.Err)))
				return
			}

			vpn.logger.Error(errors.Wrap(err, fmt.Sprintf("%T", err)))
			return
		}

		vpn.logger.Debugf("conn<%v>.ReadFromUDP(buf) -> %v (%v)", conn.LocalAddr(), err, addr)
		if err != nil {
			if err == syscall.ECONNREFUSED { // TODO: consider IP_RECVERR
				vpn.logger.Debugf("%v> ECONNREFUSED (%v), try again (to connect using for a hole punching)", conn.LocalAddr().String(), addr)
				continue
			}
			vpn.logger.Debugf("%v> unable to read message: %v (%v)", conn.LocalAddr(), err, addr)
			_ = conn.Close()
			return
		}
		if n < 2 {
			vpn.logger.Error("%v> message is too short: %v < 2 (%v)", conn.LocalAddr(), n, addr)
			continue
		}

		var reader *simpleTunnelReader
		if simpleTunnelListenerReaderCacheSize > 0 {
			for _, entry := range cache {
				if entry.HasAddress(addr) {
					reader = entry
					break
				}
			}
		}

		if reader == nil {
			vpn.logger.Debugf(`%v> cache-miss: %v`, conn.LocalAddr(), addr)

			copy(addrBuf, addr.IP)
			binary.LittleEndian.PutUint16(addrBuf[len(addr.IP):], uint16(addr.Port))
			fullAddr := addrBuf[:2+len(addr.IP)]

			readerI, err := vpn.simpleTunnelReaderMap.GetByBytes(fullAddr)
			if err != nil {
				vpn.logger.Debugf(`%v> there's no reader for %v: %v`, conn.LocalAddr(), addr, err)
				continue
			}
			reader = readerI.(*simpleTunnelReader)

			if simpleTunnelListenerReaderCacheSize > 0 {
				if len(cache) < simpleTunnelListenerReaderCacheSize {
					cache = append(cache, reader)
				} else {
					// TODO: use LRU instead:
					cache[randIntn(simpleTunnelListenerReaderCacheSize)] = reader
				}
			}
		}

		reader.enqueue(conn, addr, buf[:n])
	}
}

func (vpn *VPN) directConnectorTryNow() {
	vpn.directConnectorTrigger <- struct{}{}
}

func (vpn *VPN) directConnectorLoop() {
	ticker := time.NewTicker(60 * time.Second)
	for vpn.IsStarted() {

		// Measure latencies to peers

		for _, peer := range vpn.getPeers() {
			for _, chType := range channelTypes {
				if pingErrI := peer.SendPing(chType); pingErrI != nil {
					pingErr := pingErrI.(errors.SmartError)
					if pingErr.OriginalError() != ErrWriterIsNil {
						vpn.logger.Error(errors.Wrap(pingErr))
					}
				}
			}
		}

		// Not more than 2 iterations per second AND also wait for ping responses
		time.Sleep(time.Millisecond * 500)

		// Wait for signal to start the routines
		select {
		case <-ticker.C:
		case <-vpn.directConnectorTrigger:
			for { // If we already have a queue of requests time we should run an iteration only once, so clearing the queue
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-vpn.directConnectorTrigger:
				case <-timer.C:
				}
				timer.Stop()
			}
		}

		// Setup direct connections

		for _, peer := range vpn.getPeers() {
			chType := peer.GetOptimalChannel(channelTypeTunnel, channelTypeIPFS)
			if chType == channelType_undefined {
				continue
			}
			newDirectAddr := peer.GetRemoteRealIP(chType)
			peer.locker.Lock()
			if peer.DirectAddr == nil && peer.DirectAddr.IP.String() != newDirectAddr.String() {
				peer.DirectAddr = &net.UDPAddr{
					IP:   newDirectAddr,
					Port: ipvpnWGPortDirect,
				}
				go func(peer *Peer) {
					err := peer.Start(channelTypeDirect)
					if err != nil {
						vpn.logger.Error(errors.Wrap(err))
						return
					}
				}(peer)
			}
			peer.locker.Unlock()
		}

		// Auto-routing (use the best channel for auto-routed addresses)

		for _, peer := range vpn.getPeers() {
			chType := peer.GetOptimalChannel(channelTypeDirect, channelTypeTunnel, channelTypeIPFS)
			if chType == channelType_undefined {
				continue
			}
			err := peer.switchAutoroutedPathToChannel(chType)
			if err != nil {
				vpn.logger.Error(errors.Wrap(err))
				continue
			}
		}
	}
}

func (vpn *VPN) GetPublicKey() ed25519.PublicKey {
	return vpn.privKey.Public().(ed25519.PublicKey)
}

func (vpn *VPN) startDirectConnector() (err error) {
	defer func() { err = errors.Wrap(err) }()

	go vpn.directConnectorLoop()

	return
}

func (vpn *VPN) deleteLinks() (err error) {
	defer func() { err = errors.Wrap(err) }()

	// TODO: implement it

	return
}

func (vpn *VPN) Close() (err error) {
	if !atomic.CompareAndSwapUint32(&vpn.state, 1, 0) {
		return ErrAlreadyClosed
	}

	err0 := errors.Wrap(vpn.wgctl.Close())
	if err != nil {
		vpn.logger.Error(err0)
	}

	err1 := errors.Wrap(vpn.deleteLinks())
	if err1 != nil {
		vpn.logger.Error(err1)
	}

	err2 := vpn.simpleTunnelListener.Close()
	if err2 != nil {
		vpn.logger.Error(err2)
	}

	if err0 != nil {
		err = err0
	}
	if err1 != nil {
		err = err1
	}
	if err2 != nil {
		err = err2
	}

	return
}

func (vpn *VPN) getWGPort(chType channelType) uint16 {
	switch chType {
	case channelTypeDirect:
		return ipvpnWGPortDirect
	case channelTypeIPFS:
		return ipvpnWGPortIPFS
	case channelTypeTunnel:
		return ipvpnWGPortSimpleTunnel
	default:
		panic(fmt.Errorf(`shouldn't happened: %v`, chType))
	}
}

func (vpn *VPN) updateWireGuardConfiguration() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !vpn.IsStarted() {
		return
	}

	for _, chType := range channelTypes {
		var peersCfg []wgtypes.PeerConfig
		peersCfg, err = vpn.getPeers().ToWireGuardConfigs(chType)
		if err != nil {
			return
		}

		wgPort := int(vpn.getWGPort(chType))
		wgCfg := wgtypes.Config{
			PrivateKey:   &wgtypes.Key{},
			ListenPort:   &[]int{wgPort}[0],
			FirewallMark: &[]int{1}[0],
			Peers:        peersCfg,
			ReplacePeers: true,
		}

		// WireGuard uses Curve25519, while IPFS uses ED25519. So we need to convert it:
		{
			var privKey [64]byte
			copy(privKey[:], vpn.privKey)
			extra25519.PrivateKeyToCurve25519((*[32]byte)(wgCfg.PrivateKey), &privKey)
		}

		wgAddr := &vpn.wgnets[chType].WGListenerAddr
		wgAddr.IP = net.ParseIP(`127.0.0.1`)
		wgAddr.Port = wgPort

		vpn.logger.Debugf("wgCfg for %v with pubkey %v is %v", chType, wgCfg.PrivateKey.PublicKey(), wgCfg)

		err = vpn.wgctl.ConfigureDevice(vpn.wgnets[chType].IfaceName, wgCfg)
		if err != nil {
			return
		}
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

func (vpn *VPN) sendIntAliases(conn io.Writer) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("sendIntAlias()")

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

	n, err := conn.Write(b)
	vpn.logger.Debugf("sendIntAlias(): stream.Write(): %v %v %v", n, err, string(b))
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) recvIntAliases(conn io.Reader) (remoteIntAliases IntAliases, err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("recvIntAlias(): stream.Read()...")
	n, err := conn.Read(vpn.buffer[:])
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

	for _, chType := range channelTypes {
		var myIP net.IP
		myIP, err = vpn.GetMyIP(chType)
		if err != nil {
			return
		}

		wgnet := &vpn.wgnets[chType]
		wgnet.locker.Lock()

		if wgnet.currentIP.String() == myIP.String() {
			wgnet.locker.Unlock()
			continue
		}

		err = wgcreate.ResetIPs(wgnet.IfaceName)
		if err != nil {
			wgnet.locker.Unlock()
			return
		}

		err = wgcreate.AddIP(wgnet.IfaceName, wgnet.Subnet.IP, wgnet.Subnet)
		if err != nil {
			wgnet.locker.Unlock()
			return
		}

		wgnet.currentIP = myIP
		wgnet.locker.Unlock()
	}

	return
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

// WireGuard uses Curve25519, while IPFS uses ED25519. So we need to convert it:
func streamToWgPubKey(stream Stream) (result wgtypes.Key, err error) {
	defer func() { err = errors.Wrap(err) }()

	var pubKey [32]byte
	pubKeyBytes, err := stream.Conn().RemotePublicKey().Raw()
	if err != nil {
		return
	}
	copy(pubKey[:], pubKeyBytes)
	extra25519.PublicKeyToCurve25519((*[32]byte)(&result), &pubKey)
	return
}
func peerIDToWgPubKey(peerID peer.ID) (result wgtypes.Key, err error) {
	defer func() { err = errors.Wrap(err) }()

	pubKeyExtracted, err := peerID.ExtractPublicKey()
	if err != nil {
		return
	}

	var pubKey [32]byte
	pubKeyBytes, err := pubKeyExtracted.Raw()
	if err != nil {
		return
	}
	copy(pubKey[:], pubKeyBytes)
	extra25519.PublicKeyToCurve25519((*[32]byte)(&result), &pubKey)
	return
}

func shiftWgKey(in *wgtypes.Key) (out wgtypes.Key) {
	curve25519.ScalarMult((*[32]byte)(&out), (*[32]byte)(in), &secondaryKeyBase)
	return
}

func (vpn *VPN) newStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	return vpn.newTunnelConnection(stream, peerAddr)
}

func (vpn *VPN) NewStream(stream Stream, peerAddr AddrInfo) {
	if err := vpn.newStream(stream, peerAddr); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err := stream.Close()
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			return
		}
	}
}

func (vpn *VPN) cancelPingSenderLoop(peerID peer.ID) (r bool) {
	for {
		var cancelFunc *context.CancelFunc
		_ = vpn.pingSenderLoopCancelFunc.UnsetIf(peerID, func(value interface{}) bool {
			cancelFunc, _ = value.(*context.CancelFunc)
			return true
		})
		if cancelFunc == nil {
			break
		}
		(*cancelFunc)()
		r = true
	}

	return
}

func (vpn *VPN) newTunnelConnection(conn io.ReadWriteCloser, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()
	vpn.cancelPingSenderLoop(peerAddr.ID)

	peerID := peerAddr.ID

	wgPubKeyTunnel, err := peerIDToWgPubKey(peerID)
	if err != nil {
		return
	}
	vpn.logger.Debugf("new tunnel connection to %v, pubkey %v", peerID, wgPubKeyTunnel)

	/*
		// WireGuard doesn't support multiple endpoints for one peer, so we do a separate WireGuard
		// peer for the direct endpoint
		wgPubKeyDirect := shiftWgKey(&wgPubKeyTunnel)
	*/
	// We've separated WG interfaces, so there's no need to separate keys anymore
	wgPubKeyDirect := wgPubKeyTunnel

	vpn.newStreamLocker.Lock()
	defer vpn.newStreamLocker.Unlock()

	if peerID == vpn.myID {
		return errors.New("got a connection to myself, should not happened, ever")
	}
	err = vpn.sendIntAliases(conn)
	if err != nil {
		return
	}
	remoteIntAliases, err := vpn.recvIntAliases(conn)
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

			err = vpn.sendIntAliases(conn)
			if err != nil {
				return
			}
			remoteIntAliases, err = vpn.recvIntAliases(conn)
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
			err = vpn.sendIntAliases(conn)
			if err != nil {
				return
			}
			_, err = vpn.recvIntAliases(conn)
			if err != nil {
				return
			}
		}
	}

	isNew := false
	var peer *Peer
	if oldPeerI, _ := vpn.peers.Load(peerID); oldPeerI != nil {
		peer = oldPeerI.(*Peer)
	} else {
		peer = &Peer{
			VPN:      vpn,
			AddrInfo: peerAddr,
			IntAlias: *remoteIntAliases[0],
			WgPubKey: wgPubKeyDirect,
		}
		isNew = true
	}

	remoteIntAliases[0].Timestamp = time.Now().Add(-remoteIntAliases[0].Since)

	var chType channelType
	switch connTyped := conn.(type) {
	case Stream:
		chType = channelTypeIPFS
		_ = peer.SetIPFSStream(connTyped)
	case *udpWriter:
		chType = channelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	case *net.UDPConn:
		chType = channelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	case *udpClientSocket:
		chType = channelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	}

	err = peer.Start(chType)
	if err != nil {
		return
	}

	if isNew {
		vpn.peers.Store(peerID, peer)
	}

	saveErr := vpn.UpdateIntAliasMetadataAndSave()
	if saveErr != nil {
		vpn.logger.Error(saveErr)
	}

	return

}

func getPublicKeyFromPeerID(id peer.ID) (pubKey ed25519.PublicKey, err error) {
	defer func() { err = errors.Wrap(err) }()

	remotePubKeyI, err := id.ExtractPublicKey()
	if err != nil {
		return
	}
	remotePubKeyRaw, err := remotePubKeyI.Raw()
	if err != nil {
		return
	}
	return ed25519.PublicKey(remotePubKeyRaw), nil
}

func (vpn *VPN) pingSenderLoop(peerAddr AddrInfo, remoteUsualPort uint16, addrs []*net.UDPAddr) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	if prevCancelFunc, _ := vpn.pingSenderLoopCancelFunc.Swap(peerAddr.ID, &cancelFunc); prevCancelFunc != nil {
		(*prevCancelFunc.(*context.CancelFunc))()
	}

	defer func() {
		err := vpn.pingSenderLoopCancelFunc.UnsetIf(peerAddr.ID, func(value interface{}) bool {
			return value.(*context.CancelFunc) == &cancelFunc
		})
		if err == nil {
			cancelFunc()
		}
	}()

	sendBuf := make([]byte, sizeOfMessageType+sizeOfMessagePing)
	if err := binary.Write(bytes.NewBuffer(sendBuf), binary.LittleEndian, MessageTypePing); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		return
	}

	messagePing := MessagePing{}
	for {
		messagePing.SendTS = time.Now().UnixNano()
		err := messagePing.SignSender(vpn.privKey)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err, "unable to sign a message"))
			return
		}
		_ = messagePing.Write(sendBuf[sizeOfMessageType:])
		for _, addr := range addrs {
			var conn *net.UDPConn
			if addr.Port == int(remoteUsualPort) {
				conn = vpn.simpleTunnelListener
			} else {
				conn = vpn.simpleTunnelExternalListener
			}
			_, err := conn.WriteToUDP(sendBuf, addr)
			if err != nil {
				vpn.logger.Debugf(`%v> unable to send message: %v (%v)`, conn.LocalAddr(), err, addr)
			}
		}

		wakeuper := time.NewTimer(time.Second * time.Duration(rand.Intn(120)))
		select {
		case <-ctx.Done():
			wakeuper.Stop()
			return
		case <-wakeuper.C:
			wakeuper.Stop()
		}
	}
}

func addrToKey(addr *net.UDPAddr) []byte {
	addrBuf := make([]byte, 2+net.IPv6len)
	copy(addrBuf, addr.IP)
	binary.LittleEndian.PutUint16(addrBuf[len(addr.IP):], uint16(addr.Port))
	fullAddr := addrBuf[:2+len(addr.IP)]
	return fullAddr
}

func (vpn *VPN) createSimpleTunnelReaders(peerAddr AddrInfo, addrs []*net.UDPAddr) {
	var reader *simpleTunnelReader
	var err error
	reader, err = newSimpleTunnelReader(vpn, peerAddr, addrs, func() error { /* Close() func */
		for _, addr := range addrs {
			key := addrToKey(addr)
			_ = vpn.simpleTunnelReaderMap.UnsetIf(key, func(value interface{}) bool {
				return value.(*simpleTunnelReader) == reader
			})
		}
		return nil
	})
	if err != nil {
		vpn.logger.Error(errors.Wrap(err, `unable to create a tunnel reader`))
		return
	}

	for _, addr := range addrs {
		key := addrToKey(addr)
		// TODO: we should limit number of possible readers, otherwise it could be used for DoS attacks (to get the node run out of memory)
		_ = vpn.simpleTunnelReaderMap.Set(key, reader)
	}
}

func (vpn *VPN) startSendingPings(peerAddr AddrInfo, remoteUsualPort uint16, addrs []*net.UDPAddr) {
	vpn.createSimpleTunnelReaders(peerAddr, addrs)
	go vpn.pingSenderLoop(peerAddr, remoteUsualPort, addrs)
}

func (vpn *VPN) considerKnownPeer(peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	var remoteUsualPort uint16
	var addrs []*net.UDPAddr
	for _, maddr := range peerAddr.Addrs {
		toSkip := false
		for _, chType := range channelTypes {
			if vpn.subnetContainsMultiaddr(maddr, chType) {
				vpn.logger.Debugf(`skipping multiaddr %v: an internal VPN %v address`, maddr.String(), chType)
				toSkip = true
				break
			}
		}
		if toSkip {
			continue
		}
		addrString, err := maddr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			vpn.logger.Debugf(`skipping multiaddr %v: not an IPv4 address`, maddr.String())
			continue
		}
		ip := net.ParseIP(addrString)
		portString, err := maddr.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			vpn.logger.Debugf(`skipping multiaddr %v: not an TCP address`, maddr.String())
			continue
		}
		port, err := strconv.ParseInt(portString, 10, 64)
		if err != nil {
			vpn.logger.Error(errors.Wrap(err, `unable to parse port`, port, maddr.String()))
			continue
		}
		if ip.IsLoopback() {
			remoteUsualPort = uint16(port)
		}
		found := false
		for _, addr := range addrs {
			if addr.IP.String() == addrString && addr.Port == int(port) {
				found = true
				break
			}
		}
		if !found {
			addrs = append(addrs, &net.UDPAddr{IP: ip, Port: int(port)})
		}
	}
	for _, addr := range addrs {
		if uint16(addr.Port) != remoteUsualPort {
			addr.Port++
		}
	}

	vpn.startSendingPings(peerAddr, remoteUsualPort, addrs)
	return
}

func (vpn *VPN) ConsiderKnownPeer(peerAddr AddrInfo) {
	if err := vpn.considerKnownPeer(peerAddr); err != nil {
		vpn.logger.Error(errors.Wrap(err))
	}
}
