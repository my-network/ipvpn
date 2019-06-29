package vpn

import (
	"encoding/binary"
	"encoding/json"
	e "errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/xaionaro-go/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type channelType uint8

const (
	channelTypeUndefined = channelType(iota)
	channelTypeDirect
	channelTypeIPFS
)

const (
	peerBufferSize = 1 << 16
)

var (
	ErrUnknownMessageType = e.New("unknown message type")
	ErrMessageTooShort    = e.New(`message is too short`)
	ErrMessageFragmented  = e.New(`message was fragmented`)
	ErrInvalidSize        = e.New(`invalid size`)
)

type TrustConfig struct {
	Routing bool
}

type Peer struct {
	locker sync.Mutex

	VPN        *VPN
	Stream     Stream
	AddrInfo   AddrInfo
	IntAlias   IntAlias
	WgDirect   *wgtypes.Peer
	WgIPFS     *wgtypes.Peer
	TunnelAddr *net.UDPAddr
	TunnelConn *net.UDPConn
	IsTrusted  TrustConfig
}

type Peers []*Peer

func (peer *Peer) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	err = peer.Stream.Close()
	if err != nil {
		return
	}

	if peer.TunnelConn != nil {
		err = peer.TunnelConn.Close()
		if err != nil {
			return
		}
		peer.TunnelConn = nil
	}

	return
}

func (peer *Peer) Start() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peerDirectCfg, err := peer.toWireGuardDirectConfig()
	if err != nil {
		return
	}

	peerIPFSCfg, err := peer.toWireGuardIPFSConfig()
	if err != nil {
		return
	}

	// Setup direct connection

	cfg := wgtypes.Config{
		PrivateKey:   &wgtypes.Key{},
		ListenPort:   &[]int{ipvpnPort}[0],
		FirewallMark: &[]int{1}[0],
		Peers: []wgtypes.PeerConfig{
			peerDirectCfg,
			peerIPFSCfg,
		},
		ReplacePeers: false,
	}

	copy(cfg.PrivateKey[:], peer.VPN.privKey)

	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.ifaceName, cfg)
	if err != nil {
		return
	}

	err = peer.startTunnel()
	if err != nil {
		return
	}

	err = peer.startStreamReader()
	if err != nil {
		return
	}

	return
}

func (peer *Peer) GetID() peer.ID {
	return peer.Stream.Conn().RemotePeer()
}

func (peer *Peer) setupRoute(n net.IPNet) (err error) {
	defer func() { err = errors.Wrap(err) }()

	// TODO: implement it

	return
}

func (peer *Peer) considerConfig(cfg MessageConfig) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if peer.IsTrusted.Routing {
		for _, n := range cfg.RoutedNetworks {
			err = peer.setupRoute(n)
			if err != nil {
				return
			}
		}
	}

	return
}

func (peer *Peer) considerConfigBytes(payload []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	var cfg MessageConfig
	err = json.Unmarshal(payload, &cfg)
	if err != nil {
		return
	}

	err = peer.considerConfig(cfg)
	if err != nil {
		return
	}

	return
}

func (peer *Peer) considerPacket(b []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	size, err := peer.TunnelConn.Write(b)
	if err != nil {
		return
	}

	if size != len(b) {
		return ErrMessageFragmented
	}

	return
}

func (peer *Peer) streamReaderLoop() {
	buffer := [peerBufferSize]byte{}

	for {
		size, err := peer.Stream.Read(buffer[:])
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == io.EOF {
					peer.VPN.logger.Infof("IPFS connection closed (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
					return
				}
			}
			peer.VPN.logger.Error(errors.Wrap(err))
			_ = peer.Close()
			return
		}

		if size < 2 {
			peer.VPN.logger.Error(errors.Wrap(ErrMessageTooShort))
			_ = peer.Close()
			return
		}

		msg := buffer[:size]
		msgType := MessageType(binary.LittleEndian.Uint16(msg))
		payload := msg[2:]

		switch msgType {
		case MessageTypeConfig:
			err = peer.considerConfigBytes(payload)
		case MessageTypePacket:
			err = peer.considerPacket(payload)
		default:
			err = errors.Wrap(ErrUnknownMessageType, msgType)
		}

		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
			_ = peer.Close()
			return
		}
	}
}

func (peer *Peer) startStreamReader() (err error) {
	defer func() { err = errors.Wrap(err) }()

	go peer.streamReaderLoop()

	return
}

func (peer *Peer) switchChannel(chType channelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	// TODO: implement it

	return
}

func (peer *Peer) toWireGuardXConfig() (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	pubKey, err := peer.Stream.Conn().RemotePublicKey().Raw()
	if err != nil {
		return
	}
	internalIP, err := peer.VPN.GetIP(peer.IntAlias.Value)
	if err != nil {
		return
	}
	if err != nil {
		return
	}

	peerCfg = wgtypes.PeerConfig{
		PresharedKey:      &wgtypes.Key{},
		ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{
			{
				IP:   internalIP,
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
		},
	}
	copy(peerCfg.PublicKey[:], pubKey)
	copy(peerCfg.PresharedKey[:], peer.VPN.GetPSK())

	return
}

func (peer *Peer) toWireGuardDirectConfig() (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	peerCfg, err = peer.toWireGuardXConfig()
	if err != nil {
		return
	}
	peerIP, err := peer.Stream.Conn().RemoteMultiaddr().ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return
	}
	peerCfg.Endpoint = &net.UDPAddr{
		IP:   net.ParseIP(peerIP),
		Port: ipvpnPort,
	}

	return
}

func (peer *Peer) tunnelLoop() {
	buffer := [peerBufferSize]byte{}
	binary.LittleEndian.PutUint16(buffer[:], uint16(MessageTypePacket))

	for {
		size, err := peer.TunnelConn.Read(buffer[2:])
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == io.EOF {
					peer.VPN.logger.Infof("tunnel connection closed (peer ID %v:%v), port %v", peer.IntAlias.Value, peer.GetID(), peer.TunnelAddr.Port)
					return
				}
			}
			peer.VPN.logger.Error(errors.Wrap(err))
			_ = peer.Close()
			return
		}

		wSize, err := peer.Stream.Write(buffer[:])
		if size != wSize {
			peer.VPN.logger.Error(errors.Wrap(ErrInvalidSize, size, wSize))
			_ = peer.Close()
			return
		}
	}
}

func (peer *Peer) startTunnel() (err error) {
	defer func() { err = errors.Wrap(err) }()

	addr := &net.UDPAddr{
		IP:   net.ParseIP(`127.0.0.1`),
		Port: 0, // automatically assign a free port
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	err = udpSetNoFragment(conn)
	if err != nil {
		_ = conn.Close()
		return
	}

	addrString := conn.LocalAddr().String()
	port, err := strconv.ParseInt(addrString[strings.LastIndex(addrString, `:`)+1:], 10, 64)
	if err != nil {
		_ = conn.Close()
		return
	}
	addr.Port = int(port)

	peer.TunnelAddr = addr
	peer.TunnelConn = conn

	go peer.tunnelLoop()

	return
}

func (peer *Peer) toWireGuardIPFSConfig() (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	peerCfg, err = peer.toWireGuardXConfig()
	if err != nil {
		return
	}

	peerCfg.Endpoint = peer.TunnelAddr
	return
}

func (peers Peers) toWireGuardConfigs() (result []wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, peer := range peers {
		peerDirectCfg, err := peer.toWireGuardDirectConfig()
		if err != nil {
			return nil, err
		}
		result = append(result, peerDirectCfg)

		peerIPFSCfg, err := peer.toWireGuardIPFSConfig()
		if err != nil {
			return nil, err
		}
		result = append(result, peerIPFSCfg)
	}
	return
}
