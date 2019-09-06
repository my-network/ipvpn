package vpn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	e "errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/agl/ed25519/extra25519"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/wgcreate"
	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	bufferSize                  = 1 << 20
	ipvpnIfaceNamePrefix        = `ipvpn_`
	defaultMTU                  = 1280
	ipvpnTunnelPortSimpleTunnel = 18294
	directConnectionTimeout     = 30 * time.Second
)

var (
	ErrAlreadyClosed      = e.New(`already closed`)
	ErrAlreadyStarted     = e.New(`already started`)
	ErrWrongMessageLength = e.New(`wrong message length`)
	ErrInvalidPeerID      = e.New(`invalid peer ID`)
)

type Stream = network.Stream
type AddrInfo = network.AddrInfo

type VPN struct {
	Config

	locker sync.RWMutex

	logger                       Logger
	mesh                         *network.Network
	myID                         peer.ID
	ifaceNamePrefix              string
	dirPath                      string
	peers                        sync.Map
	buffer                       [bufferSize]byte
	privKey                      ed25519.PrivateKey
	psk                          []byte
	state                        uint32
	wgctl                        *wgctrl.Client
	wgnets                       [ChannelType_max]WGNet
	directConnectorTrigger       chan struct{}
	simpleTunnelListener         *net.UDPConn
	simpleTunnelExternalListener *net.UDPConn
	simpleTunnelReaderMap        atomicmap.Map
	upperHandlers                []UpperHandler

	newIncomingStreamChan chan struct {
		Stream
		AddrInfo
	}
	onPeerConnectChan                chan peer.ID
	considerKnownPeerChan            chan AddrInfo
	updateWireGuardConfigurationChan chan struct{}
	setupIfaceIPAddressesChan        chan struct{}

	pingSenderLoopCancelFunc atomicmap.Map
}

func New(dirPath string, subnet net.IPNet, logger Logger) (vpn *VPN, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err)
			vpn = nil
		}
	}()

	vpn = &VPN{
		logger:                 logger,
		dirPath:                dirPath,
		ifaceNamePrefix:        ipvpnIfaceNamePrefix,
		directConnectorTrigger: make(chan struct{}, 256),
		newIncomingStreamChan: make(chan struct {
			Stream
			AddrInfo
		}),
		onPeerConnectChan:                make(chan peer.ID),
		considerKnownPeerChan:            make(chan AddrInfo),
		updateWireGuardConfigurationChan: make(chan struct{}),
		setupIfaceIPAddressesChan:        make(chan struct{}),

		simpleTunnelReaderMap:    atomicmap.New(),
		pingSenderLoopCancelFunc: atomicmap.New(),
	}

	// Splitting "subnet" to 4 subnets: direct, ipfs, simpleTunnel, autoRouted
	{
		maskOnes, maskBits := subnet.Mask.Size()
		maskOnes += 2 // Splitting the subnet to 4, so in each mask amount of one's is increased to 2
		newMask := net.CIDRMask(maskOnes, maskBits)
		for idx, chType := range ChannelTypes {
			wgnet := &vpn.wgnets[chType]
			wgnet.Subnet.IP, err = getIPByOffset(subnet.IP, uint64(idx)*1<<uint(maskBits-maskOnes))
			wgnet.Subnet.Mask = newMask
		}
	}

	vpn.wgctl, err = wgctrl.New()
	if err != nil {
		return
	}

	err = vpn.LoadConfig()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) LockDo(fn func()) {
	vpn.locker.Lock()
	defer vpn.locker.Unlock()
	fn()
}

func (vpn *VPN) RLockDo(fn func()) {
	vpn.locker.RLock()
	defer vpn.locker.RUnlock()
	fn()
}

func (vpn *VPN) SetNetwork(mesh *network.Network) {
	vpn.logger.Debugf(`SetNetwork`)

	vpn.LockDo(func() {
		vpn.mesh = mesh

		// TODO: unset the handlers on Close()
		mesh.SetMessageHandler(TopicRequestDirectPort, vpn.handleRequestDirectPort)
		mesh.SetMessageHandler(TopicRequestSimpleTunnelPort, vpn.handleRequestSimpleTunnelPort)
		mesh.SetMessageHandler(TopicUpdateDirectPort, vpn.handleUpdateDirectPort)
		mesh.SetMessageHandler(TopicUpdateSimpleTunnelPort, vpn.handleUpdateSimpleTunnelPort)
	})
}

func (vpn *VPN) handleRequestDirectPort(stream Stream, payload []byte) {
	vpn.logger.Debugf(`handleRequestDirectPort`)

	vpn.notifyPeerAboutMyPort(stream.Conn().RemotePeer(), ChannelTypeDirect, vpn.Config.DirectWGPort)
}

func (vpn *VPN) handleRequestSimpleTunnelPort(stream Stream, payload []byte) {
	vpn.logger.Debugf(`handleRequestSimpleTunnelPort`)

	vpn.notifyPeerAboutMyPort(stream.Conn().RemotePeer(), ChannelTypeTunnel, vpn.Config.SimpleTunnelPort)
}

func (vpn *VPN) handleUpdateDirectPort(stream Stream, payload []byte) {
	vpn.logger.Debugf(`handleUpdateDirectPort`)

	if len(payload) != 2 {
		vpn.logger.Error(errors.Wrap(ErrWrongMessageLength, len(payload), payload))
		return
	}

	peerID := stream.Conn().RemotePeer().String()
	peerConfig := vpn.Peers[peerID]
	peerConfig.DirectWGPort = binary.LittleEndian.Uint16(payload)
	vpn.Peers[peerID] = peerConfig

	warnErr := vpn.SaveConfig()
	if warnErr != nil {
		vpn.logger.Error(errors.Wrap(warnErr))
	}
}

func (vpn *VPN) handleUpdateSimpleTunnelPort(stream Stream, payload []byte) {
	vpn.logger.Debugf(`handleUpdateSimpleTunnelPort`)

	if len(payload) != 2 {
		vpn.logger.Error(errors.Wrap(ErrWrongMessageLength, len(payload), payload))
		return
	}

	peerID := stream.Conn().RemotePeer().String()
	peerConfig := vpn.Peers[peerID]
	peerConfig.SimpleTunnelPort = binary.LittleEndian.Uint16(payload)
	vpn.Peers[peerID] = peerConfig

	warnErr := vpn.SaveConfig()
	if warnErr != nil {
		vpn.logger.Error(errors.Wrap(warnErr))
	}
}

func (vpn *VPN) ProtocolID() protocol.ID {
	return `/p2p/github.com/my-network/ipvpn/vpn`
}

func (vpn *VPN) AddUpperHandler(upperHandler UpperHandler) {
	vpn.logger.Debugf(`AddUpperHandler`)
	vpn.logger.Debugf(`/AddUpperHandler`)

	vpn.LockDo(func() {
		vpn.upperHandlers = append(vpn.upperHandlers, upperHandler)
	})
}

func (vpn *VPN) GetNetworkMaximalSize() uint64 {
	vpn.logger.Debugf(`GetNetworkMaximalSize`)

	addressLength := net.IPv6len * 8
	subnet := vpn.wgnets[ChannelTypeDirect].Subnet
	_, bits := subnet.Mask.Size()
	if subnet.IP.To4() != nil {
		addressLength = net.IPv4len * 8
	}
	return (1 << uint(addressLength-bits)) - 3
}

func (vpn *VPN) SetID(newID peer.ID) {
	vpn.logger.Debugf(`SetID`)

	vpn.LockDo(func() {
		vpn.myID = newID
		vpn.Config.IntAlias.PeerID = vpn.myID
	})

	err := vpn.SaveConfig()
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

func (vpn *VPN) GetIP(intAlias uint64, chType ChannelType) (resultIP net.IP, err error) {
	defer func() { err = errors.Wrap(err) }()
	defer func() { vpn.logger.Debugf("GetIP(%v, %v) -> %v, %v", intAlias, chType, resultIP, err) }()

	vpn.logger.Debugf(`GetIP`)

	subnet := vpn.wgnets[chType].Subnet

	maskOnes, maskBits := subnet.Mask.Size()
	if intAlias >= 1<<uint32(maskBits-maskOnes) {
		return nil, errors.New("int alias value is too big or subnet is too small")
	}

	return getIPByOffset(subnet.IP, intAlias)
}

func (vpn *VPN) subnetContainsMultiaddr(maddr multiaddr.Multiaddr, chType ChannelType) bool {
	addr4, err := maddr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return false
	}

	subnet := vpn.wgnets[chType].Subnet
	return subnet.Contains(net.ParseIP(addr4))
}

func (vpn *VPN) IsBadAddress(maddr multiaddr.Multiaddr) bool {
	return vpn.subnetContainsMultiaddr(maddr, ChannelTypeIPFS)
}

func (vpn *VPN) GetMyIP(chType ChannelType) (net.IP, error) {
	return vpn.GetIP(vpn.IntAlias.Value, chType)
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

	vpn.logger.Debugf(`Start`)
	defer vpn.logger.Debugf(`/Start`)

	if !atomic.CompareAndSwapUint32(&vpn.state, 0, 1) {
		return ErrAlreadyStarted
	}

	for _, chType := range ChannelTypes {
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

	simpleTunnelListener, warnErr := net.ListenUDP("udp", &net.UDPAddr{
		Port: ipvpnTunnelPortSimpleTunnel,
	})
	if warnErr != nil {
		vpn.logger.Error(errors.Wrap(warnErr, `unable to start listening the default simple tunnel port`))
		return
	} else {
		vpn.simpleTunnelListener = simpleTunnelListener
		go vpn.simpleTunnelListenerReader(simpleTunnelListener)
	}

	err = vpn.restartSimpleTunnelExternalListener(vpn.SimpleTunnelPort)
	if err != nil {
		return
	}

	err = vpn.startCallChanHandler()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) startCallChanHandler() error {
	go vpn.callChanHandlerLoop()
	return nil
}

func (vpn *VPN) callChanHandlerLoop() {
	for vpn.IsStarted() {
		vpn.logger.Debugf(`callChanHandlerLoop(): waiting...`)
		var err error
		select {
		case args := <-vpn.newIncomingStreamChan:
			err = vpn.newIncomingStream(args.Stream, args.AddrInfo)
		case peerID := <-vpn.onPeerConnectChan:
			err = vpn.onPeerConnect(peerID)
		case peerAddr := <-vpn.considerKnownPeerChan:
			err = vpn.considerKnownPeer(peerAddr)
		case <-vpn.updateWireGuardConfigurationChan:
			err = vpn.updateWireGuardConfiguration()
		case <-vpn.setupIfaceIPAddressesChan:
			err = vpn.setupIfaceIPAddresses()
		}
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
		}
	}
}

func (vpn *VPN) restartSimpleTunnelExternalListener(port uint16) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("restartSimpleTunnelExternalListener(%v)", port)

	if vpn.simpleTunnelExternalListener != nil {
		_ = vpn.simpleTunnelExternalListener.Close()
	}

	var simpleTunnelExternalListener *net.UDPConn
	simpleTunnelExternalListener, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: int(port),
	})
	if err != nil {
		return
	}

	if port == 0 {
		port = uint16(simpleTunnelExternalListener.LocalAddr().(*net.UDPAddr).Port)
		if port == 0 {
			panic(`shouldn't happened`)
		}
	}

	vpn.simpleTunnelExternalListener = simpleTunnelExternalListener
	go vpn.simpleTunnelListenerReader(simpleTunnelExternalListener)

	vpn.SimpleTunnelPort = port

	vpn.notifyPeersAboutMyPort(ChannelTypeTunnel, port)

	warnErr := vpn.SaveConfig()
	if warnErr != nil {
		vpn.logger.Infof(`unable to notify about my simple tunnel external port: %v`, warnErr)
	}
	return
}

func (vpn *VPN) notifyPeerAboutMyPort(peerID peer.ID, chType ChannelType, port uint16) {
	var topic string
	switch chType {
	case ChannelTypeDirect:
		topic = TopicUpdateDirectPort
	case ChannelTypeTunnel:
		topic = TopicUpdateSimpleTunnelPort
	default:
		panic(fmt.Errorf(`unknown channel type: %v`, chType))
	}

	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	warnErr := vpn.mesh.SendMessage(peerID, topic, buf)
	if warnErr != nil {
		vpn.logger.Infof(`unable to notify peer %v about my %v port: %v`, peerID, chType.String(), warnErr)
	}
}

func (vpn *VPN) notifyPeersAboutMyPort(chType ChannelType, port uint16) {
	var topic string
	switch chType {
	case ChannelTypeDirect:
		topic = TopicUpdateDirectPort
	case ChannelTypeTunnel:
		topic = TopicUpdateSimpleTunnelPort
	default:
		panic(fmt.Errorf(`unknown channel type: %v`, chType))
	}

	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	warnErr := vpn.mesh.SendBroadcastMessage(topic, buf)
	if warnErr != nil {
		vpn.logger.Infof(`unable to notify about my %v port: %v`, chType.String(), warnErr)
	}
}

func (vpn *VPN) SetMyAddrs(addrs []multiaddr.Multiaddr) {
}

func (vpn *VPN) getPeerPort(peerID peer.ID, chType ChannelType) uint16 {
	switch chType {
	case ChannelTypeDirect:
		return vpn.Peers[peerID.String()].DirectWGPort
	case ChannelTypeTunnel:
		return vpn.Peers[peerID.String()].SimpleTunnelPort
	default:
		panic(fmt.Errorf(`unknown channel type: %v`, chType))
	}
	return 0
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

func (vpn *VPN) PrivKey() (r ed25519.PrivateKey) {
	vpn.RLockDo(func() {
		r = vpn.privKey
	})
	return r
}

func (vpn *VPN) requestPortInfo(peerID peer.ID, chType ChannelType) {
	var topic string
	switch chType {
	case ChannelTypeDirect:
		topic = TopicRequestDirectPort
	case ChannelTypeTunnel:
		topic = TopicRequestSimpleTunnelPort
	default:
		panic(fmt.Errorf(`unknown channel type: %v`, chType))
	}
	err := vpn.mesh.SendMessage(peerID, topic, nil)
	if err != nil {
		switch err.(errors.SmartError).OriginalError() {
		case network.ErrPeerNotFound:
			vpn.logger.Debugf(`peer %v not found (requestPortInfo: %v)`, peerID, chType)
		default:
			vpn.logger.Error(errors.Wrap(err, peerID, topic))
		}
	}
}

func (vpn *VPN) directConnectorLoop() {
	ticker := time.NewTicker(60 * time.Second)
	for vpn.IsStarted() {

		// Measure latencies to peers

		vpn.logger.Debugf(`directConnectorLoop(): starting a measuring of latencies to peers`)
		for _, peer := range vpn.getPeers() {
			for _, chType := range ChannelTypes {
				if pingErrI := peer.SendPing(chType); pingErrI != nil {
					pingErr := pingErrI.(errors.SmartError)
					if pingErr.OriginalError() != ErrWriterIsNil {
						vpn.logger.Error(errors.Wrap(pingErr))
					}
				}

				// TODO: reduce traffic consumption
				vpn.requestPortInfo(peer.ID, ChannelTypeDirect)
				vpn.requestPortInfo(peer.ID, ChannelTypeTunnel)
			}
		}

		// Not more than 2 iterations per second AND also wait for ping responses
		time.Sleep(time.Millisecond * 500)

		// Wait for signal to start the routines
		vpn.logger.Debugf(`directConnectorLoop(): waiting`)
		select {
		case <-ticker.C:
		case <-vpn.directConnectorTrigger:
			timer := time.NewTimer(time.Millisecond)
			finishedWaiting := false
			for finishedWaiting { // If we already have a queue of requests time we should run an iteration only once, so clearing the queue
				select {
				case <-vpn.directConnectorTrigger:
				case <-timer.C:
					finishedWaiting = true
				}
			}
			timer.Stop()
		}

		// Setup direct connections

		vpn.logger.Debugf(`directConnectorLoop(): trying to setup direct connections`)
		for _, peer := range vpn.getPeers() {
			chType := peer.GetOptimalChannel(ChannelTypeTunnel, ChannelTypeIPFS)
			vpn.logger.Debugf(`directConnectorLoop(): trying to setup a direct connection to %v. Optimal channel: %v`, peer.ID, chType)
			if chType == ChannelType_undefined {
				continue
			}

			peer.SwitchDirectChannelToPathOfChannel(chType)
		}

		// Auto-routing (use the best channel for auto-routed addresses)

		for _, peer := range vpn.getPeers() {
			chType := peer.GetOptimalChannel(ChannelTypeDirect, ChannelTypeTunnel, ChannelTypeIPFS)
			if chType == ChannelType_undefined {
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
	return vpn.PrivKey().Public().(ed25519.PublicKey)
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

	var err2 error
	if vpn.simpleTunnelListener != nil {
		vpn.logger.Debugf(`Close(): simpleTunnelListener != nil`)

		err2 = vpn.simpleTunnelListener.Close()
		if err2 != nil {
			vpn.logger.Error(err2)
		}
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

	close(vpn.considerKnownPeerChan)
	close(vpn.newIncomingStreamChan)
	close(vpn.onPeerConnectChan)

	return
}

func (vpn *VPN) getWGPort(chType ChannelType) uint16 {
	switch chType {
	case ChannelTypeDirect:
		return vpn.DirectWGPort
	case ChannelTypeIPFS:
		return vpn.IPFSWGPort
	case ChannelTypeTunnel:
		return vpn.SimpleTunnelWGPort
	default:
		panic(fmt.Errorf(`shouldn't happened: %v`, chType))
	}
}

func (vpn *VPN) updateWireGuardConfiguration() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !vpn.IsStarted() {
		return
	}

	for _, chType := range ChannelTypes {
		var peersCfg []wgtypes.PeerConfig
		peersCfg, err = vpn.getPeers().ToWireGuardConfigs(chType)
		if err != nil {
			return
		}

		wgPort := int(vpn.getWGPort(chType))
		wgCfg := wgtypes.Config{
			PrivateKey:   &wgtypes.Key{},
			ListenPort:   &[]int{wgPort}[0],
			FirewallMark: &[]int{192 + int(chType)}[0],
			Peers:        peersCfg,
			ReplacePeers: true,
		}

		// WireGuard uses Curve25519, while IPFS uses ED25519. So we need to convert it:
		{
			var privKey [64]byte
			copy(privKey[:], vpn.PrivKey())
			extra25519.PrivateKeyToCurve25519((*[32]byte)(wgCfg.PrivateKey), &privKey)
		}

		// On MacOS function vpn.wgctl.ConfigureDevice hangs sometimes, so we were have to add this hacks here :(
		{
			tryingToConfigureTheDevice := true
			endChan := make(chan struct{})
			for tryingToConfigureTheDevice {
				go func() {
					vpn.logger.Debugf("wgCfg for %v (interface: %v) with pubkey %v is %v", chType, vpn.wgnets[chType].IfaceName, wgCfg.PrivateKey.PublicKey(), wgCfg)

					err = vpn.wgctl.ConfigureDevice(vpn.wgnets[chType].IfaceName, wgCfg)
					endChan <- struct{}{}
					if err != nil {
						return
					}

					vpn.logger.Debugf("/wgCfg for %v (interface: %v) with pubkey %v is %v", chType, vpn.wgnets[chType].IfaceName, wgCfg.PrivateKey.PublicKey(), wgCfg)
				}()

				waitTimer := time.NewTimer(time.Second * 5)
				select {
				case <-endChan:
					waitTimer.Stop()
					tryingToConfigureTheDevice = false
					continue
				case <-waitTimer.C:
					vpn.logger.Error(`timed-out`)
					vpn.wgnets[chType].IfaceName, err = wgcreate.Create(vpn.ifaceNamePrefix+chType.String(), defaultMTU, true, &device.Logger{
						Debug: log.New(vpn.logger.GetDebugWriter(), "[wireguard-"+chType.String()+"] ", 0),
						Info:  log.New(vpn.logger.GetInfoWriter(), "[wireguard-"+chType.String()+"] ", 0),
						Error: log.New(vpn.logger.GetErrorWriter(), "[wireguard-"+chType.String()+"] ", 0),
					})
				}
			}
			close(endChan)
		}

		if wgPort == 0 {
			var dev *wgtypes.Device
			dev, err = vpn.wgctl.Device(vpn.wgnets[chType].IfaceName)
			if err != nil {
				return
			}
			wgPort = dev.ListenPort
			if wgPort == 0 {
				panic(`shouldn't happened :(`)
			}

			switch chType {
			case ChannelTypeDirect:
				vpn.DirectWGPort = uint16(wgPort)
			case ChannelTypeIPFS:
				vpn.IPFSWGPort = uint16(wgPort)
			case ChannelTypeTunnel:
				vpn.SimpleTunnelWGPort = uint16(wgPort)
			}
			warnErr := vpn.SaveConfig()
			if warnErr != nil {
				vpn.logger.Error(errors.Wrap(warnErr))
			}

			switch chType {
			case ChannelTypeDirect, ChannelTypeTunnel:
				vpn.notifyPeersAboutMyPort(chType, uint16(wgPort))
			}
		}

		wgAddr := &vpn.wgnets[chType].WGListenerAddr
		wgAddr.IP = net.ParseIP(`127.0.0.1`)
		wgAddr.Port = wgPort
	}

	err = vpn.setupIfaceIPAddresses()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) UpdateWireGuardConfiguration() {
	go func() {
		vpn.updateWireGuardConfigurationChan <- struct{}{}
	}()
}

func (vpn *VPN) SetPrivateKey(privKey ed25519.PrivateKey) {
	vpn.LockDo(func() {
		vpn.setPrivateKey(privKey)
	})
	vpn.UpdateWireGuardConfiguration()
}

func (vpn *VPN) setPSK(psk []byte) {
	vpn.psk = psk
}

func (vpn *VPN) SetPSK(psk []byte) {
	vpn.LockDo(func() {
		vpn.setPSK(psk)
	})
	vpn.UpdateWireGuardConfiguration()
}

func (vpn *VPN) GetPSK() (r []byte) {
	vpn.RLockDo(func() {
		r = vpn.psk
	})
	return
}

func (vpn *VPN) setupIfaceIPAddress(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	var myIP net.IP
	myIP, err = vpn.GetMyIP(chType)
	if err != nil {
		return
	}

	wgnet := &vpn.wgnets[chType]

	if wgnet.currentIP.String() == myIP.String() {
		return
	}

	err = wgcreate.ResetIPs(wgnet.IfaceName)
	if err != nil {
		return
	}

	vpn.logger.Debugf(`wgcreate.AddIP("%v", "%v", "%v")`, wgnet.IfaceName, myIP, wgnet.Subnet)
	err = wgcreate.AddIP(wgnet.IfaceName, myIP, wgnet.Subnet)
	if err != nil {
		return
	}

	wgnet.currentIP = myIP
	return
}

func (vpn *VPN) setupIfaceIPAddresses() (err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, chType := range ChannelTypes {
		if err = vpn.setupIfaceIPAddress(chType); err != nil {
			return
		}
	}

	return
}

func (vpn *VPN) SetIntAlias(newValue uint64) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("SetIntAlias: %v->%v", vpn.IntAlias.Value, newValue)

	vpn.LockDo(func() {
		vpn.IntAlias.Value = newValue
		vpn.IntAlias.Timestamp = time.Now()
	})

	vpn.setupIfaceIPAddressesChan <- struct{}{}
	return
}

func (vpn *VPN) GetIntAlias() (r IntAlias) {
	vpn.RLockDo(func() {
		r = vpn.Config.IntAlias
	})
	return
}

func (vpn *VPN) GetNetworkSize() (result uint64) {
	result = 1 // myself is already "1"

	vpn.peers.Range(func(_, _ interface{}) bool {
		result++
		return true
	})

	return
}

func (vpn *VPN) LoadConfig() (err error) {
	defer func() { err = errors.Wrap(err) }()

	configData, readErr := ioutil.ReadFile(filepath.Join(vpn.dirPath, `config.json`))
	if readErr == nil {
		vpn.LockDo(func() {
			err = vpn.Config.Unmarshal(configData)
			if err != nil {
				return
			}
			if vpn.IntAlias.Timestamp.UnixNano() < time.Date(2019, 06, 23, 19, 47, 29, 0, time.UTC).UnixNano() { // if the computer has a broken battery and the clock shows wrong value
				vpn.IntAlias.Timestamp = time.Now()
			}
		})
	} else {
		vpn.LockDo(func() {
			vpn.IntAlias.Value = 1
			vpn.IntAlias.Timestamp = time.Now()
			vpn.IntAlias.MaxNetworkSize = 1
		})
	}

	vpn.LockDo(func() {
		if vpn.Peers == nil {
			vpn.Peers = map[string]PeerConfig{}
		}
	})

	return
}

func (vpn *VPN) SaveConfig() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if vpn.Config.IntAlias.PeerID == "" {
		return ErrInvalidPeerID
	}

	err = os.MkdirAll(vpn.dirPath, 0750)
	if err != nil {
		return err
	}

	configPath := filepath.Join(vpn.dirPath, `config.json`)
	vpn.logger.Debugf("saving the config %v to %v", vpn.Config, configPath)
	defer vpn.logger.Debugf("endof: saving the config %v to %v", vpn.Config, configPath)

	curNetworkSize := vpn.GetNetworkSize()
	vpn.LockDo(func() {
		if curNetworkSize > vpn.IntAlias.MaxNetworkSize {
			vpn.IntAlias.MaxNetworkSize = curNetworkSize
			vpn.IntAlias.Timestamp = time.Now()
		}
	})

	var b []byte
	vpn.RLockDo(func() {
		b, err = vpn.Config.Marshal()
	})
	if err != nil {
		return
	}

	vpn.LockDo(func() {
		err = ioutil.WriteFile(configPath+"-new", b, 0644)
		if err != nil {
			return
		}

		_ = os.Remove(configPath)

		err = os.Rename(configPath+"-new", configPath)
		if err != nil {
			return
		}
	})

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

/*func shiftWgKey(in *wgtypes.Key) (out wgtypes.Key) {
	curve25519.ScalarMult((*[32]byte)(&out), (*[32]byte)(in), &secondaryKeyBase)
	return
}*/

func (vpn *VPN) GetOrCreatePeerByID(peerID peer.ID) (result *Peer) {
	vpn.logger.Debugf(`GetOrCreatePeerByID: %v`, peerID)

	if peerID == vpn.myID {
		vpn.logger.Error(errors.New("got a connection to myself, should not happened, ever"))
		return
	}

	wgPubKey, err := peerIDToWgPubKey(peerID)
	if err != nil {
		vpn.logger.Error(`unable to get a key for WG using peer ID: "%v"`, peerID)
		return
	}

	if oldPeerI, _ := vpn.peers.Load(peerID); oldPeerI != nil {
		return oldPeerI.(*Peer)
	}

	vpn.logger.Infof(`now I know about a new peer %v, pubkey %v`, peerID, wgPubKey.String())
	result = &Peer{
		ID:       peerID,
		VPN:      vpn,
		WgPubKey: wgPubKey,
	}
	vpn.peers.Store(peerID, result)

	result.Start()

	return
}

func (vpn *VPN) newIncomingStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()
	vpn.logger.Debugf(`newIncomingStream from %v`, peerAddr.ID)

	peer := vpn.GetOrCreatePeerByID(peerAddr.ID)

	if err := peer.NewIncomingStream(stream, peerAddr); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err2 := stream.Close()
		if err2 != nil {
			vpn.logger.Error(errors.Wrap(err2))
		}
	}
	return
}

func (vpn *VPN) NewIncomingStream(stream Stream, peerAddr AddrInfo) {
	vpn.logger.Debugf(`NewIncomingStream from %v`, peerAddr.ID)

	go func() {
		vpn.newIncomingStreamChan <- struct {
			Stream
			AddrInfo
		}{stream, peerAddr}
	}()
}

func (vpn *VPN) OnPeerConnect(peerID peer.ID) {
	vpn.logger.Debugf(`OnPeerConnect("%v")`, peerID)

	go func() {
		vpn.onPeerConnectChan <- peerID
	}()
}

func (vpn *VPN) onPeerConnect(peerID peer.ID) error {
	vpn.logger.Debugf(`onPeerConnect("%v")`, peerID)
	peer := vpn.GetOrCreatePeerByID(peerID)

	go func() {
		peer.RLockDo(func() {
			if peer.isFinished() {
				return
			}
			peer.onNoControlStreamsLeftChan <- struct{}{}
			peer.onNoForwarderStreamsLeftChan <- struct{}{}
		})
	}()
	return nil
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
			if remoteUsualPort != 0 && addr.Port != int(remoteUsualPort) {
				conn = vpn.simpleTunnelExternalListener
			} else {
				conn = vpn.simpleTunnelListener
			}
			if conn == nil {
				vpn.logger.Error(errors.Wrap(fmt.Errorf(`conn == nil: %v %v`, addr.Port, remoteUsualPort)))
				continue
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

	vpn.requestPortInfo(peerAddr.ID, ChannelTypeDirect)
	vpn.requestPortInfo(peerAddr.ID, ChannelTypeTunnel)

	var remoteUsualPort uint16
	var addrs []*net.UDPAddr
	for _, maddr := range peerAddr.Addrs {
		toSkip := false
		for _, chType := range ChannelTypes {
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
			portString, err = maddr.ValueForProtocol(multiaddr.P_UDP)
			if err != nil {
				vpn.logger.Debugf(`skipping multiaddr %v: not an TCP/UDP address`, maddr.String())
				continue
			}
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

	if remoteUsualPort > 0 {
		var newAddrs []*net.UDPAddr
		for _, addr := range addrs {
			if uint16(addr.Port) != remoteUsualPort {
				for _, newAddr := range addrs {
					if newAddr.IP.String() == addr.String() && uint16(newAddr.Port) != remoteUsualPort {
						continue
					}
				}
				addr.Port = int(vpn.getPeerPort(peerAddr.ID, ChannelTypeTunnel))
				if addr.Port == 0 {
					continue
				}
			}
			newAddrs = append(newAddrs, addr)
		}
		addrs = newAddrs
	}

	vpn.startSendingPings(peerAddr, remoteUsualPort, addrs)
	return
}

func (vpn *VPN) ConsiderKnownPeer(peerAddr AddrInfo) {
	vpn.considerKnownPeerChan <- peerAddr
}

func (vpn *VPN) ReconnectToPeer(peerID peer.ID) {
	vpn.mesh.ClosePeer(peerID)
	vpn.mesh.ConnectPeer(peerID)
}
