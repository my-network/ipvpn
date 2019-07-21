package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	e "errors"
	"fmt"
	"github.com/libp2p/go-libp2p-core/protocol"
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

	ID                          peer.ID
	VPN                         *VPN
	IntAlias                    IntAlias
	DirectAddr                  *net.UDPAddr
	IPFSControlStreamIngoing    Stream
	IPFSControlStreamOutgoing   Stream
	IPFSForwarderStreamIngoing  Stream
	IPFSForwarderStreamOutgoing Stream
	IPFSTunnelAddrToWG          *net.UDPAddr
	IPFSTunnelConnToWG          *net.UDPConn
	SimpleTunnelConn            net.Conn
	SimpleTunnelConnToWG        *net.UDPConn
	SimpleTunnelAddrToWG        *net.UDPAddr
	IsTrusted                   TrustConfig
	WgPubKey                    wgtypes.Key
	channelStatistics           [ChannelType_max]channelStatistics

	ingoingForwarderStreamTunnelWriterRunning  bool
	outgoingForwarderStreamTunnelWriterRunning bool
	ingoingForwarderStreamTunnelReaderRunning  bool
	outgoingForwarderStreamTunnelReaderRunning bool
	ingoingControlStreamTunnelReaderRunning    bool
	outgoingControlStreamTunnelReaderRunning   bool
}

type Peers []*Peer

func (peer *Peer) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	if peer.IPFSControlStreamIngoing != nil {
		err = peer.IPFSControlStreamIngoing.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSControlStreamIngoing = nil
	}

	if peer.IPFSControlStreamOutgoing != nil {
		err = peer.IPFSControlStreamOutgoing.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSControlStreamOutgoing = nil
	}

	if peer.IPFSForwarderStreamIngoing != nil {
		err = peer.IPFSForwarderStreamIngoing.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSForwarderStreamIngoing = nil
	}

	if peer.IPFSForwarderStreamOutgoing != nil {
		err = peer.IPFSForwarderStreamOutgoing.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSForwarderStreamOutgoing = nil
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

func (peer *Peer) configureDevice(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.locker.Lock()
	defer peer.locker.Unlock()

	if peer.IPFSTunnelConnToWG == nil {
		if peer.IPFSTunnelConnToWG, peer.IPFSTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
			IP:   net.ParseIP(`127.0.0.1`),
			Port: 0, // automatically assign a free port
		}); err != nil {
			return
		}
	}

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

	peer.VPN.logger.Debugf(`configuring device %v for peer %v`, peer.VPN.wgnets[chType].IfaceName, peer.ID)
	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.wgnets[chType].IfaceName, wgCfg)
	if err != nil {
		return
	}

	return
}

func (peer *Peer) onNoControlStreamsLeft() {
	vpn := peer.VPN

	vpn.logger.Debugf("no control streams left, peer.ID == %v", peer.ID)

	outgoingStream := helpers.NewReconnectableStream(vpn.logger, func() (Stream, error) {
		return vpn.mesh.NewStream(peer.ID, vpn.ProtocolID()+`/control/`+protocol.ID(vpn.myID.String()))
	})

	outgoingStream.Connect()

	vpn.logger.Debugf(`New outgoing control stream for peer %v`, peer.ID)

	err := peer.AddControlStream(outgoingStream, AddrInfo{ID: peer.ID})
	if err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err := outgoingStream.Close()
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			return
		}
	}
}

func (peer *Peer) onNoForwarderStreamsLeft() {
	vpn := peer.VPN

	vpn.logger.Debugf("no forwarder streams left, peer.ID == %v", peer.ID)

	outgoingStream := helpers.NewReconnectableStream(vpn.logger, func() (Stream, error) {
		return vpn.mesh.NewStream(peer.ID, vpn.ProtocolID()+`/wg/`+protocol.ID(vpn.myID.String()))
	})

	outgoingStream.Connect()

	vpn.logger.Debugf(`New outgoing traffic forward stream for peer %v`, peer.ID)

	err := peer.AddTunnelConnection(outgoingStream, AddrInfo{ID: peer.ID})
	if err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err := outgoingStream.Close()
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			return
		}
	}
}

func (peer *Peer) AddControlStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	switch connTyped := stream.(type) {
	case *helpers.ReconnectableStream:
		_ = peer.SetIPFSControlStream(connTyped, true)
	case Stream:
		_ = peer.SetIPFSControlStream(connTyped, false)
	default:
		panic(`should not happened`)
	}

	peer.VPN.logger.Debugf("calling peer.StartControlStream()")

	err = peer.StartControlStream()
	if err != nil {
		return
	}

	return
}

func (peer *Peer) AddTunnelConnection(conn io.ReadWriteCloser, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn := peer.VPN

	vpn.logger.Debugf("new tunnel connection to %v", peer.ID)
	defer vpn.logger.Debugf("finished to setup of a new tunnel connection to %v", peer.ID)

	vpn.newStreamLocker.Lock()
	defer vpn.newStreamLocker.Unlock()

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
		if remoteIntAlias.PeerID == vpn.IntAlias.PeerID {
			continue
		}
		remoteIntAlias.Timestamp = time.Now().Add(-remoteIntAlias.Since)
		notMyIntAliases[remoteIntAlias.Value] = remoteIntAlias
	}
	if remoteIntAliases[0].Value == vpn.IntAlias.Value {
		changeOnRemoteSide := false
		if vpn.IntAlias.MaxNetworkSize > remoteIntAliases[0].MaxNetworkSize {
			changeOnRemoteSide = true
		} else if vpn.IntAlias.MaxNetworkSize == remoteIntAliases[0].MaxNetworkSize {
			if vpn.IntAlias.Timestamp.UnixNano() > remoteIntAliases[0].Timestamp.UnixNano() {
				changeOnRemoteSide = true
			} else if vpn.IntAlias.Timestamp.UnixNano() == remoteIntAliases[0].Timestamp.UnixNano() {
				if vpn.myID < peer.ID {
					changeOnRemoteSide = true
				}
			}
		}

		if changeOnRemoteSide {
			vpn.logger.Debugf("int alias collision, remote side should change it's alias %v <?= %v , %v <?= %v, %v >? %v",
				vpn.IntAlias.Value, remoteIntAliases[0].Value,
				vpn.IntAlias.Timestamp, remoteIntAliases[0].Timestamp,
				vpn.myID, peer.ID)

			err = vpn.sendIntAliases(conn)
			if err != nil {
				return
			}
			remoteIntAliases, err = vpn.recvIntAliases(conn)
			if err != nil {
				return
			}
			if remoteIntAliases[0].Value == vpn.IntAlias.Value {
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

			warnErr := vpn.SaveConfig()
			if warnErr != nil {
				vpn.logger.Error(errors.Wrap(err))
			}
		}
	}

	vpn.logger.Debugf("negotiations with %v are complete", peerAddr.ID)

	remoteIntAliases[0].Timestamp = time.Now().Add(-remoteIntAliases[0].Since)

	peer.IntAlias = *remoteIntAliases[0]

	var chType ChannelType
	switch connTyped := conn.(type) {
	case *helpers.ReconnectableStream:
		chType = ChannelTypeIPFS
		_ = peer.SetIPFSForwarderStream(connTyped, true)
	case Stream:
		chType = ChannelTypeIPFS
		_ = peer.SetIPFSForwarderStream(connTyped, false)
	case *udpWriter:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	case *net.UDPConn:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	case *udpClientSocket:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		_ = peer.SetSimpleTunnelConn(connTyped)
	}

	vpn.logger.Debugf("peer.Start(%v)", chType)

	err = peer.Start(chType)
	if err != nil {
		return
	}

	saveErr := vpn.SaveConfig()
	if saveErr != nil {
		vpn.logger.Error(saveErr)
	}

	return

}

func (peer *Peer) StartControlStream() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.StartControlStream()`, peer.ID)
	defer peer.VPN.logger.Debugf(`endof peer<%v>.StartControlStream()`, peer.ID)

	peer.locker.Lock()
	defer peer.locker.Unlock()

	if peer.IPFSControlStreamIngoing != nil && !peer.ingoingControlStreamTunnelReaderRunning {
		peer.VPN.logger.Debugf(`peer<%v>.StartControlStream(): starting ingoing stream reader`, peer.ID)
		peer.ingoingControlStreamTunnelReaderRunning = true
		go func(stream Stream) {
			peer.controlStreamReaderLoop(peer.IPFSControlStreamIngoing)
			peer.VPN.logger.Debugf(`endof peer<%v>.controlStreamReaderLoop(peer.IPFSControlStreamIngoing)`, peer.ID)
			peer.locker.Lock()
			peer.ingoingControlStreamTunnelReaderRunning = false
			if peer.IPFSControlStreamIngoing == stream {
				peer.VPN.logger.Debugf(`peer<%v>.IPFSControlStreamIngoing = nil`, peer.ID)
				_ = peer.IPFSControlStreamIngoing.Close()
				peer.IPFSControlStreamIngoing = nil
			}
			if peer.IPFSControlStreamOutgoing == nil {
				peer.VPN.logger.Debugf(`peer<%v>.IPFSControlStreamOutgoing == nil`, peer.ID)
				go peer.onNoControlStreamsLeft()
			}
			peer.locker.Unlock()

		}(peer.IPFSControlStreamIngoing)
	}

	if peer.IPFSControlStreamOutgoing != nil && !peer.outgoingControlStreamTunnelReaderRunning {
		peer.VPN.logger.Debugf(`peer<%v>.StartControlStream(): starting outgoing stream reader`, peer.ID)
		peer.outgoingControlStreamTunnelReaderRunning = true
		go func(stream Stream) {
			peer.controlStreamReaderLoop(peer.IPFSControlStreamOutgoing)
			peer.VPN.logger.Debugf(`endof peer<%v>.controlStreamReaderLoop(peer.IPFSControlStreamOutgoing)`, peer.ID)
			peer.locker.Lock()
			peer.outgoingControlStreamTunnelReaderRunning = false
			if peer.IPFSControlStreamOutgoing == stream {
				peer.VPN.logger.Debugf(`peer<%v>.IPFSControlStreamOutgoing = nil`, peer.ID)
				_ = peer.IPFSControlStreamOutgoing.Close()
				peer.IPFSControlStreamOutgoing = nil
			}
			if peer.IPFSControlStreamIngoing == nil {
				peer.VPN.logger.Debugf(`peer<%v>.IPFSControlStreamIngoing == nil`, peer.ID)
				go peer.onNoControlStreamsLeft()
			}
			peer.locker.Unlock()
		}(peer.IPFSControlStreamOutgoing)
	}

	return
}

func (peer *Peer) Start(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	err = peer.configureDevice(chType)
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

func (peer *Peer) considerPongBytes(pongBytes []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	var pong MessagePong
	if err = pong.Read(pongBytes); err != nil {
		return
	}

	if err = peer.considerPong(ChannelTypeIPFS, &pong); err != nil {
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

func (peer *Peer) controlStreamReaderLoop(conn io.ReadWriteCloser) {
	buffer := [peerBufferSize]byte{}

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
			err = peer.considerPongBytes(payload)
		case MessageTypeConfig:
			err = peer.considerConfigBytes(payload)
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

func (peer *Peer) tunnelToWgForwarderLoop(conn io.ReadWriteCloser) {
	buffer := [peerBufferSize]byte{}

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

		err = peer.forwardPacketToWG(buffer[:size], conn)
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

	peer.locker.Lock()
	defer peer.locker.Unlock()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSForwarderStreamIngoing != nil && !peer.ingoingForwarderStreamTunnelReaderRunning {
			peer.ingoingForwarderStreamTunnelReaderRunning = true
			go func(stream Stream) {
				ingoingConn := newUDPWriter(peer.IPFSTunnelConnToWG, stream, &peer.VPN.wgnets[chType].WGListenerAddr)
				peer.tunnelToWgForwarderLoop(ingoingConn)
				peer.VPN.logger.Debugf(`endof peer<%v>.tunnelToWgForwarderLoop(ingoingConn)`, peer.ID)
				peer.locker.Lock()
				peer.ingoingForwarderStreamTunnelReaderRunning = false
				if peer.IPFSForwarderStreamIngoing == stream {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamIngoing = nil`, peer.ID)
					_ = peer.IPFSForwarderStreamIngoing.Close()
					peer.IPFSForwarderStreamIngoing = nil
				}
				if peer.IPFSForwarderStreamOutgoing == nil {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamOutgoing == nil`, peer.ID)
					go peer.onNoForwarderStreamsLeft()
				}
				peer.locker.Unlock()
			}(peer.IPFSForwarderStreamIngoing)
		}

		if peer.IPFSForwarderStreamOutgoing != nil && !peer.outgoingForwarderStreamTunnelReaderRunning {
			peer.outgoingForwarderStreamTunnelReaderRunning = true
			go func(stream Stream) {
				outgoingConn := newUDPWriter(peer.IPFSTunnelConnToWG, stream, &peer.VPN.wgnets[chType].WGListenerAddr)
				peer.tunnelToWgForwarderLoop(outgoingConn)
				peer.VPN.logger.Debugf(`endof peer<%v>.tunnelToWgForwarderLoop(outgoingConn)`, peer.ID)
				peer.locker.Lock()
				peer.outgoingForwarderStreamTunnelReaderRunning = false
				if peer.IPFSForwarderStreamOutgoing == stream {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamOutgoing = nil`, peer.ID)
					_ = peer.IPFSForwarderStreamOutgoing.Close()
					peer.IPFSForwarderStreamOutgoing = nil
				}
				if peer.IPFSForwarderStreamIngoing == nil {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamIngoing == nil`, peer.ID)
					go peer.onNoForwarderStreamsLeft()
				}
				peer.locker.Unlock()
			}(peer.IPFSForwarderStreamOutgoing)
		}
	case ChannelTypeTunnel:
		conn := newUDPWriter(peer.SimpleTunnelConnToWG, peer.SimpleTunnelConn, &peer.VPN.wgnets[chType].WGListenerAddr)
		go peer.tunnelToWgForwarderLoop(conn)
	default:
		panic(fmt.Errorf("invalid channel type: %v", chType))
	}

	return
}

func (peer *Peer) SendPing(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	switch chType {
	case ChannelTypeDirect, ChannelTypeTunnel:
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
	case ChannelTypeIPFS:
		writer := peer.IPFSControlStream()
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
		ipfsStream := peer.IPFSControlStream()
		if ipfsStream == nil {
			return nil
		}
		maddr := ipfsStream.Conn().RemoteMultiaddr()
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

	for {
		size, err := wgConn.Read(buffer[:])
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

		wSize, err := tunnelConn.Write(buffer[:size])
		if size != wSize {
			peer.VPN.logger.Error(errors.Wrap(ErrInvalidSize, size, wSize))
			err = peer.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		if err != nil {
			peer.VPN.logger.Infof(`unable to write to tunnel connection: %v`, err)
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

func (peer *Peer) stopIPFSForwarderStream(isOutgoing bool) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if isOutgoing {
		if peer.IPFSForwarderStreamOutgoing != nil {
			_ = peer.IPFSForwarderStreamOutgoing.Close()
			peer.IPFSForwarderStreamOutgoing = nil
		}
	} else {
		if peer.IPFSForwarderStreamIngoing != nil {
			_ = peer.IPFSForwarderStreamIngoing.Close()
			peer.IPFSForwarderStreamIngoing = nil
		}
	}

	return
}

func (peer *Peer) stopIPFSControlStream(isOutgoing bool) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if isOutgoing {
		if peer.IPFSControlStreamOutgoing != nil {
			_ = peer.IPFSControlStreamOutgoing.Close()
			peer.IPFSControlStreamOutgoing = nil
		}
	} else {
		if peer.IPFSControlStreamIngoing != nil {
			_ = peer.IPFSControlStreamIngoing.Close()
			peer.IPFSControlStreamIngoing = nil
		}
	}

	return
}

func (peer *Peer) IPFSControlStream() Stream {
	peer.locker.RLock()
	defer peer.locker.RUnlock()
	if peer.IPFSControlStreamIngoing != nil {
		return peer.IPFSControlStreamIngoing
	}

	return peer.IPFSControlStreamOutgoing
}

func (peer *Peer) SetIPFSControlStream(stream Stream, isOutgoing bool) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.SetIPFSControlStream("%v", %v)`, peer.ID, stream.Conn().RemotePeer(), isOutgoing)
	defer peer.VPN.logger.Debugf(`endof peer<%v>.SetIPFSControlStream("%v", %v)`, peer.ID, stream.Conn().RemotePeer(), isOutgoing)

	peer.locker.Lock()
	defer peer.locker.Unlock()
	_ = peer.stopIPFSControlStream(isOutgoing)

	if isOutgoing {
		peer.IPFSControlStreamOutgoing = stream
	} else {
		peer.IPFSControlStreamIngoing = stream
	}

	return
}

func (peer *Peer) SetIPFSForwarderStream(stream Stream, isOutgoing bool) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.SetIPFSForwarderStream("%v", %v)`, peer.ID, stream.Conn().RemotePeer(), isOutgoing)
	defer peer.VPN.logger.Debugf(`endof peer<%v>.SetIPFSForwarderStream("%v", %v)`, peer.ID, stream.Conn().RemotePeer(), isOutgoing)

	peer.locker.Lock()
	defer peer.locker.Unlock()
	_ = peer.stopIPFSForwarderStream(isOutgoing)

	if isOutgoing {
		peer.IPFSForwarderStreamOutgoing = stream
	} else {
		peer.IPFSForwarderStreamIngoing = stream
	}

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

	peer.locker.Lock()
	defer peer.locker.Unlock()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSTunnelConnToWG == nil {
			panic(`should not happen`)
		}
		if peer.IPFSForwarderStreamIngoing != nil && !peer.ingoingForwarderStreamTunnelWriterRunning {
			peer.ingoingForwarderStreamTunnelWriterRunning = true
			go func(stream Stream) {
				peer.wgToTunnelForwarderLoop(peer.IPFSTunnelConnToWG, stream)
				peer.VPN.logger.Debugf(`endof peer<%v>.wgToTunnelForwarderLoop(peer.IPFSTunnelConnToWG, peer.IPFSForwarderStreamIngoing)`, peer.ID)
				peer.locker.Lock()
				peer.ingoingForwarderStreamTunnelWriterRunning = false
				if peer.IPFSForwarderStreamIngoing == stream {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamIngoing = nil`, peer.ID)
					_ = peer.IPFSForwarderStreamIngoing.Close()
					peer.IPFSForwarderStreamIngoing = nil
				}
				peer.locker.Unlock()
			}(peer.IPFSForwarderStreamIngoing)
		}
		if peer.IPFSForwarderStreamOutgoing != nil && !peer.outgoingForwarderStreamTunnelWriterRunning {
			peer.outgoingForwarderStreamTunnelWriterRunning = true
			go func(stream Stream) {
				peer.wgToTunnelForwarderLoop(peer.IPFSTunnelConnToWG, stream)
				peer.VPN.logger.Debugf(`endof peer<%v>.wgToTunnelForwarderLoop(peer.IPFSTunnelConnToWG, peer.IPFSForwarderStreamOutgoing)`, peer.ID)
				peer.locker.Lock()
				peer.outgoingForwarderStreamTunnelWriterRunning = false
				if peer.IPFSForwarderStreamOutgoing == stream {
					peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStreamOutgoing = nil`, peer.ID)
					_ = peer.IPFSForwarderStreamOutgoing.Close()
					peer.IPFSForwarderStreamOutgoing = nil
				}
				peer.locker.Unlock()
			}(peer.IPFSForwarderStreamOutgoing)
		}
	case ChannelTypeTunnel:
		if peer.SimpleTunnelConnToWG == nil {
			if peer.SimpleTunnelConnToWG, peer.SimpleTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
				IP:   net.ParseIP(`127.0.0.1`),
				Port: 0, // automatically assign a free port
			}); err != nil {
				return
			}
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
