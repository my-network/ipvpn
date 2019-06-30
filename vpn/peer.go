package vpn

import (
	"encoding/binary"
	"encoding/json"
	e "errors"
	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p/p2p/net/mock"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

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

	VPN            *VPN
	Stream         Stream
	AddrInfo       AddrInfo
	IntAlias       IntAlias
	DirectAddr     *net.UDPAddr
	TunnelAddr     *net.UDPAddr
	TunnelConn     *net.UDPConn
	IsTrusted      TrustConfig
	WgPubKeyDirect wgtypes.Key
	WgPubKeyTunnel wgtypes.Key
}

type Peers []*Peer

func (peer *Peer) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	err = peer.Stream.Close()
	if err != nil {
		peer.VPN.logger.Error(errors.Wrap(err))
	}

	if peer.TunnelConn != nil {
		err = peer.TunnelConn.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.TunnelConn = nil
	}

	peer.VPN.peers.Delete(peer.GetID())
	peer.VPN.logger.Debugf("peer closed %v %v", peer.IntAlias.Value, peer.GetID())

	return
}

func (peer *Peer) Start() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peerDirectCfg, err := peer.toWireGuardDirectConfig()
	if err != nil {
		return
	}

	peer.DirectAddr = peerDirectCfg.Endpoint

	err = peer.startTunnel()
	if err != nil {
		return
	}

	peerIPFSCfg, err := peer.toWireGuardIPFSConfig()
	if err != nil {
		return
	}

	// Setup tunneled connection

	cfgTunnel := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerIPFSCfg,
		},
	}

	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.ifaceNameTunnel, cfgTunnel)
	if err != nil {
		return
	}

	// Setup direct connection

	cfgDirect := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerDirectCfg,
		},
	}

	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.ifaceNameDirect, cfgDirect)
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

	size, err := peer.TunnelConn.WriteToUDP(b, &peer.VPN.wgListenerTunnelAddr)
	if err != nil {
		if err == syscall.EDESTADDRREQ {
			peer.VPN.logger.Debugf("WG is not connected to the tunnel, yet. Peer %v %v", peer.IntAlias.Value, peer.GetID())
			return nil
		}
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
			if err == mux.ErrReset || err == io.EOF || err == mocknet.ErrReset || err.Error() == "stream reset" {
				peer.VPN.logger.Infof("IPFS connection closed (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
			} else {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			err := peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		if size < 2 {
			peer.VPN.logger.Error(errors.Wrap(ErrMessageTooShort))
			err := peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
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
			err := peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
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

func (peer *Peer) toWireGuardXConfig(isSecondary bool) (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	internalIP, err := peer.VPN.GetIP(peer.IntAlias.Value, isSecondary)
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
	copy(peerCfg.PresharedKey[:], peer.VPN.GetPSK())

	peer.VPN.logger.Debugf("peerCfg: %v", peerCfg)

	return
}

func (peer *Peer) toWireGuardDirectConfig() (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	peerCfg, err = peer.toWireGuardXConfig(true)
	if err != nil {
		return
	}
	peerIP, err := peer.Stream.Conn().RemoteMultiaddr().ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return
	}

	copy(peerCfg.PublicKey[:], peer.WgPubKeyDirect[:])
	peerCfg.Endpoint = &net.UDPAddr{
		IP:   net.ParseIP(peerIP),
		Port: ipvpnPortDirect,
	}

	peer.VPN.logger.Debugf("peer %v, direct endpoint %v", peer.GetID(), peerCfg.Endpoint)

	return
}

func (peer *Peer) tunnelLoop() {
	buffer := [peerBufferSize]byte{}
	binary.LittleEndian.PutUint16(buffer[:], uint16(MessageTypePacket))

	for {
		size, err := peer.TunnelConn.Read(buffer[2:])
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == io.EOF || netErr.Err.Error() == "use of closed network connection" {
					peer.VPN.logger.Infof("tunnel connection closed (peer ID %v:%v), port %v", peer.IntAlias.Value, peer.GetID(), peer.TunnelAddr.Port)
					err := peer.Close()
					if err != nil {
						peer.VPN.logger.Error(errors.Wrap(err))
					}
					return
				}
			}
			peer.VPN.logger.Error(errors.Wrap(err))
			err := peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		wSize, err := peer.Stream.Write(buffer[:size+2])
		if size+2 != wSize {
			peer.VPN.logger.Error(errors.Wrap(ErrInvalidSize, size, wSize))
			err = peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
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

	peerCfg, err = peer.toWireGuardXConfig(false)
	if err != nil {
		return
	}

	copy(peerCfg.PublicKey[:], peer.WgPubKeyTunnel[:])
	peerCfg.Endpoint = peer.TunnelAddr

	peer.VPN.logger.Debugf("peer %v, IPFS endpoint %v", peer.GetID(), peerCfg.Endpoint)
	return
}

func (peers Peers) toWireGuardDirectConfigs() (result []wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, peer := range peers {
		peerDirectCfg, err := peer.toWireGuardDirectConfig()
		if err != nil {
			return nil, err
		}
		result = append(result, peerDirectCfg)
	}
	return
}

func (peers Peers) toWireGuardTunnelConfigs() (result []wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, peer := range peers {
		peerIPFSCfg, err := peer.toWireGuardIPFSConfig()
		if err != nil {
			return nil, err
		}
		result = append(result, peerIPFSCfg)
	}
	return
}
