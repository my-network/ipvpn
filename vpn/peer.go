package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	e "errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
	"github.com/my-network/ipvpn/helpers"
	"github.com/xaionaro-go/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	peerBufferSize = 1 << 16
)

var (
	ErrUnknownMessageType = e.New("unknown message type")
	ErrMessageTooShort    = e.New(`message is too short`)
	ErrMessageFragmented  = e.New(`message was fragmented`)
	ErrInvalidSize        = e.New(`invalid size`)
	ErrNegativeRTT        = e.New(`negative RTT`)
	ErrWriterIsNil        = e.New(`writer is nil`)
)

type TrustConfig struct {
	Routing bool
}

type Peer struct {
	locker sync.RWMutex

	ID                   peer.ID
	VPN                  *VPN
	AddrInfo             AddrInfo
	IntAlias             IntAlias
	DirectAddr           *net.UDPAddr
	IPFSStream           Stream
	IPFSTunnelAddrToWG   *net.UDPAddr
	IPFSTunnelConnToWG   *net.UDPConn
	SimpleTunnelConn     net.Conn
	SimpleTunnelConnToWG *net.UDPConn
	SimpleTunnelAddrToWG *net.UDPAddr
	IsTrusted            TrustConfig
	WgPubKey             wgtypes.Key
	channelStatistics    [ChannelType_max]channelStatistics
}

type Peers []*Peer

func (peer *Peer) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	err = peer.IPFSStream.Close()
	if err != nil {
		peer.VPN.logger.Error(errors.Wrap(err))
	}

	if peer.IPFSTunnelConnToWG != nil {
		err = peer.IPFSTunnelConnToWG.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSTunnelConnToWG = nil
	}

	if peer.SimpleTunnelConn != nil {
		err = peer.SimpleTunnelConn.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.SimpleTunnelConn = nil
	}

	if peer.SimpleTunnelConnToWG != nil {
		err = peer.SimpleTunnelConnToWG.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.SimpleTunnelConnToWG = nil
	}

	peer.VPN.peers.Delete(peer.GetID())
	peer.VPN.logger.Debugf("peer closed %v %v", peer.IntAlias.Value, peer.GetID())

	return
}

func (peer *Peer) Start(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	var peerCfg wgtypes.PeerConfig
	peerCfg, err = peer.toWireGuardConfig(chType)
	if err != nil {
		return
	}

	wgCfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerCfg,
		},
	}

	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.wgnets[chType].IfaceName, wgCfg)
	if err != nil {
		return
	}

	err = peer.startTunnelWriter(chType)
	if err != nil {
		return
	}

	err = peer.startTunnelReader(chType)
	if err != nil {
		return
	}

	go func() {
		for _, duration := range []time.Duration{
			time.Second,
			2 * time.Second,
			4 * time.Second,
			7 * time.Second,
			10 * time.Second,
			20 * time.Second,
			30 * time.Second,
			40 * time.Second,
		} {
			time.Sleep(duration)
			peer.VPN.directConnectorTryNow()
		}
	}()

	return
}

func (peer *Peer) GetID() peer.ID {
	return peer.ID
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

func (peer *Peer) GetPublicKey() ed25519.PublicKey {
	publicKeyExtracted, err := peer.GetID().ExtractPublicKey()
	if err != nil {
		panic(err)
	}
	publicKey, err := publicKeyExtracted.Raw()
	if err != nil {
		panic(err)
	}
	return ed25519.PublicKey(publicKey)
}

func (peer *Peer) replyWithPong(pingBytes []byte, writer io.Writer) (err error) {
	defer func() { err = errors.Wrap(err) }()

	recvTS := time.Now()

	var pong MessagePong
	if err = pong.MessagePing.Read(pingBytes); err != nil {
		return
	}

	if signErr := pong.VerifySender(peer.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof("invalid sender signature of an incoming ping message from peer %v: %v", peer.GetID(), signErr)
		return
	}

	pong.ReceiveTS = recvTS.UnixNano()
	pong.SendTS = time.Now().UnixNano()
	if err = pong.SignRecipient(peer.VPN.privKey); err != nil {
		return
	}

	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.LittleEndian, MessageTypePong); err != nil {
		return
	}
	if err = binary.Write(&buf, binary.LittleEndian, pong.Bytes()); err != nil {
		return
	}

	if _, err = writer.Write(buf.Bytes()); err != nil {
		return
	}

	return
}

func (peer *Peer) considerRTT(chType ChannelType, rtt time.Duration) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if rtt.Nanoseconds() < 0 {
		return errors.Wrap(ErrNegativeRTT, rtt.Nanoseconds())
	}

	stats := &peer.channelStatistics[chType]
	stats.locker.Lock()

	inertiaFactor := float64(stats.SamplesCount)
	if inertiaFactor > 5 {
		inertiaFactor = 5
	}

	// stats.RTT = (oldRTT * 5 + newRTT) / 6
	stats.RTT = time.Nanosecond * time.Duration(uint64(
		(float64(stats.RTT.Nanoseconds())*inertiaFactor+float64(rtt.Nanoseconds()))/
			(inertiaFactor+1)))

	stats.SamplesCount++

	stats.locker.Unlock()

	return
}

func (peer *Peer) considerPong(chType ChannelType, pong *MessagePong) (err error) {
	defer func() { err = errors.Wrap(err) }()

	recvTS := time.Now()

	if signErr := pong.VerifySender(peer.VPN.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof(`invalid sender signature in a pong message from peer %v: %v`, peer.ID, signErr)
		return
	}

	if signErr := pong.VerifyRecipient(peer.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof(`invalid recipient signature in a pong message from peer %v: %v`, peer.ID, signErr)
		return
	}

	if err = peer.considerRTT(chType, recvTS.Sub(time.Unix(0, pong.MessagePing.SendTS))); err != nil {
		return
	}

	return
}

func (peer *Peer) considerPongBytes(chType ChannelType, pongBytes []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	var pong MessagePong
	if err = pong.Read(pongBytes); err != nil {
		return
	}

	if err = peer.considerPong(chType, &pong); err != nil {
		return
	}

	return
}

func (peer *Peer) forwardPacketToWG(b []byte, writer io.Writer) (err error) {
	defer func() { err = errors.Wrap(err) }()

	size, err := writer.Write(b)
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

func (peer *Peer) tunnelToWgForwarderLoop(chType ChannelType) {
	buffer := [peerBufferSize]byte{}

	var conn io.ReadWriter
	switch chType {
	case ChannelTypeIPFS:
		conn = newUDPWriter(peer.IPFSTunnelConnToWG, peer.IPFSStream, &peer.VPN.wgnets[chType].WGListenerAddr)
	case ChannelTypeTunnel:
		conn = newUDPWriter(peer.SimpleTunnelConnToWG, peer.SimpleTunnelConn, &peer.VPN.wgnets[chType].WGListenerAddr)
	default:
		panic(fmt.Errorf("invalid channel type: %v", chType))
	}

	for {
		size, err := conn.Read(buffer[:])
		if err != nil {
			if err == mux.ErrReset || err == io.EOF || err == mocknet.ErrReset || err.Error() == "service conn reset" {
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
		case MessageTypePing:
			err = peer.replyWithPong(payload, conn)
		case MessageTypePong:
			err = peer.considerPongBytes(chType, payload)
		case MessageTypeConfig:
			err = peer.considerConfigBytes(payload)
		case MessageTypePacket:
			err = peer.forwardPacketToWG(payload, conn)
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

func (peer *Peer) startTunnelReader(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	switch chType {
	case ChannelTypeIPFS, ChannelTypeTunnel:
		go peer.tunnelToWgForwarderLoop(chType)
	}

	return
}

func (peer *Peer) SendPing(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	switch chType {
	case ChannelTypeDirect:
		var remoteVPNIP net.IP
		if remoteVPNIP, err = peer.VPN.GetIP(peer.IntAlias.Value, ChannelTypeDirect); err != nil {
			return
		}
		go func() {
			ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
			rtt := helpers.MeasureLatency(ctx, remoteVPNIP, peer.VPN.logger)
			if rtt.Nanoseconds() >= math.MaxUint64/128 {
				return
			}
			if err = peer.considerRTT(chType, rtt); err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
		}()
	case ChannelTypeIPFS, ChannelTypeTunnel:
		var writer io.Writer
		switch chType {
		case ChannelTypeIPFS:
			writer = peer.IPFSStream
		case ChannelTypeTunnel:
			writer = peer.SimpleTunnelConn
		}
		if writer == nil {
			return ErrWriterIsNil
		}

		var ping MessagePing
		ping.SequenceID = 0
		ping.SendTS = time.Now().UnixNano()
		if err = ping.SignSender(peer.VPN.privKey); err != nil {
			return
		}
		var buf bytes.Buffer
		if err = binary.Write(&buf, binary.LittleEndian, MessageTypePing); err != nil {
			return
		}
		buf.Write(ping.Bytes())

		if _, err = writer.Write(buf.Bytes()); err != nil {
			return
		}
	default:
		panic(fmt.Errorf(`shouldn't happened: %v`, chType))
	}
	return
}

func (peer *Peer) GetRemoteRealIP(chType ChannelType) net.IP {
	peer.locker.RLock()
	defer peer.locker.RUnlock()

	switch chType {
	case ChannelTypeDirect:
		if peer.DirectAddr == nil {
			return nil
		}
		return peer.DirectAddr.IP
	case ChannelTypeIPFS:
		if peer.IPFSStream == nil {
			return nil
		}
		maddr := peer.IPFSStream.Conn().RemoteMultiaddr()
		addr4String, err := maddr.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			peer.VPN.logger.Debugf(`unable to parse IPv4 address from multiaddr %v`, maddr)
			return nil
		}
		return net.ParseIP(addr4String)
	case ChannelTypeTunnel:
		if peer.SimpleTunnelConn == nil {
			return nil
		}
		return net.ParseIP(strings.Split(peer.SimpleTunnelConn.RemoteAddr().String(), `:`)[0])
	}

	panic(fmt.Errorf(`shouldn't happened: %v'`, chType))
	return nil
}

func (peer *Peer) GetOptimalChannel(chTypes ...ChannelType) (optimalChannelType ChannelType) {
	optimalChannelType = ChannelType_undefined
	minRTT := time.Duration(time.Hour)

	for _, chType := range chTypes {
		stats := &peer.channelStatistics[chType]
		stats.locker.RLock()
		if stats.SamplesCount == 0 {
			stats.locker.RUnlock()
			continue
		}

		if stats.RTT.Nanoseconds() < minRTT.Nanoseconds() {
			minRTT = stats.RTT
			optimalChannelType = chType
		}

		stats.locker.RUnlock()
	}

	return
}

func (peer *Peer) switchAutoroutedPathToChannel(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Infof("switching the auto-routed address for %v to %v", peer.ID, chType)

	// TODO: implement it

	return
}

func (peer *Peer) toWireGuardConfig(chType ChannelType) (peerCfg wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	internalIP, err := peer.VPN.GetIP(peer.IntAlias.Value, chType)
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
	copy(peerCfg.PublicKey[:], peer.WgPubKey[:])
	peerCfg.PersistentKeepaliveInterval = &[]time.Duration{time.Second * time.Duration(30)}[0]

	peer.VPN.logger.Debugf("peerCfg: %v", peerCfg)

	switch chType {
	case ChannelTypeDirect:
		peerCfg.Endpoint = peer.DirectAddr
	case ChannelTypeIPFS:
		peerCfg.Endpoint = peer.IPFSTunnelAddrToWG
	case ChannelTypeTunnel:
		peerCfg.Endpoint = peer.SimpleTunnelAddrToWG
	}

	peer.VPN.logger.Debugf("peer %v, %v endpoint %v", peer.GetID(), chType, peerCfg.Endpoint)

	return
}

func (peer *Peer) wgToTunnelForwarderLoop(wgConn io.Reader, tunnelConn io.Writer) {
	buffer := [peerBufferSize]byte{}
	binary.LittleEndian.PutUint16(buffer[:], uint16(MessageTypePacket))

	for {
		size, err := wgConn.Read(buffer[2:])
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == io.EOF || netErr.Err.Error() == "use of closed network connection" {
					peer.VPN.logger.Infof("tunnel connection closed (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
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

		wSize, err := tunnelConn.Write(buffer[:size+2])
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

func newUDPListener(addrIn *net.UDPAddr) (conn *net.UDPConn, addr *net.UDPAddr, err error) {
	defer func() { err = errors.Wrap(err) }()
	addr = addrIn

	conn, err = net.ListenUDP("udp", addr)
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

	return
}

func (peer *Peer) stopIPFSStream() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if peer.IPFSStream != nil {
		_ = peer.IPFSStream.Close()
	}
	if peer.IPFSTunnelConnToWG != nil {
		_ = peer.IPFSTunnelConnToWG.Close()
	}

	return
}

func (peer *Peer) SetIPFSStream(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()
	_ = peer.stopIPFSStream()
	peer.IPFSStream = stream

	return
}

func (peer *Peer) stopSimpleTunnelConn() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if peer.SimpleTunnelConn != nil {
		_ = peer.SimpleTunnelConn.Close()
	}
	if peer.SimpleTunnelConnToWG != nil {
		_ = peer.SimpleTunnelConnToWG.Close()
	}

	return nil
}

func (peer *Peer) SetSimpleTunnelConn(conn net.Conn) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()
	_ = peer.stopSimpleTunnelConn()
	peer.SimpleTunnelConn = conn

	return
}

func (peer *Peer) startTunnelWriter(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSTunnelConnToWG, peer.IPFSTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
			IP:   net.ParseIP(`127.0.0.1`),
			Port: 0, // automatically assign a free port
		}); err != nil {
			return
		}
		go peer.wgToTunnelForwarderLoop(peer.IPFSTunnelConnToWG, peer.IPFSStream)
	case ChannelTypeTunnel:
		if peer.SimpleTunnelConnToWG, peer.SimpleTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
			IP:   net.ParseIP(`127.0.0.1`),
			Port: 0, // automatically assign a free port
		}); err != nil {
			return
		}
		go peer.wgToTunnelForwarderLoop(peer.SimpleTunnelConnToWG, peer.SimpleTunnelConn)
	}

	return
}

func (peers Peers) ToWireGuardConfigs(chType ChannelType) (result []wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, peer := range peers {
		peer.locker.Lock()
		peerDirectCfg, err := peer.toWireGuardConfig(chType)
		peer.locker.Unlock()
		if err != nil {
			return nil, err
		}
		result = append(result, peerDirectCfg)
	}
	return
}
