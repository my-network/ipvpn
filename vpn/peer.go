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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
	"github.com/xaionaro-go/bytesextra"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/my-network/ipvpn/helpers"
)

const (
	peerBufferSize           = 1 << 16
	receiveIntAliasesTimeout = time.Second * 30
)

var (
	ErrUnknownMessageType = e.New("unknown message type")
	ErrMessageTooShort    = e.New(`message is too short`)
	ErrMessageFragmented  = e.New(`message was fragmented`)
	ErrInvalidSize        = e.New(`invalid size`)
	ErrNegativeRTT        = e.New(`negative RTT`)
	ErrWriterIsNil        = e.New(`writer is nil`)
	ErrUnexpectedCount    = e.New(`unexpected count`)
)

type TrustConfig struct {
	Routing bool
}

type Peer struct {
	locker sync.RWMutex

	ID                       peer.ID
	VPN                      *VPN
	IntAlias                 IntAlias
	DirectAddr               *net.UDPAddr
	IPFSControlStream        Stream
	IPFSForwarderStream      Stream
	IPFSTunnelAddrToWG       *net.UDPAddr
	IPFSTunnelConnToWG       *net.UDPConn
	SimpleTunnelConn         net.Conn
	SimpleTunnelConnToWG     *net.UDPConn
	SimpleTunnelAddrToWG     *net.UDPAddr
	IsTrusted                TrustConfig
	WgPubKey                 wgtypes.Key
	channelStatistics        [ChannelType_max]channelStatistics
	LastSuccessfulPingTS     atomic.Value
	LastSuccessfulIPFSPingTS atomic.Value

	onNoForwarderStreamsLeftConcurrency    int32
	context                                context.Context
	contextCancelFunc                      context.CancelFunc
	onNoControlStreamsLeftChan             chan struct{}
	onNoForwarderStreamsLeftChan           chan struct{}
	startChannelChan                       chan ChannelType
	setIPFSForwarderStreamChan             chan Stream
	switchDirectChannelToPathOfChannelChan chan ChannelType

	forwarderStreamTunnelWriterRunning bool
	forwarderStreamTunnelReaderRunning bool
	controlStreamTunnelReaderRunning   bool
}

type Peers []*Peer

func (peer *Peer) LockDo(fn func()) {
	peer.locker.Lock()
	defer peer.locker.Unlock()

	fn()
}

func (peer *Peer) RLockDo(fn func()) {
	peer.locker.RLock()
	defer peer.locker.RUnlock()

	fn()
}

func (peer *Peer) Start() {
	peer.LockDo(func() {
		peer.context, peer.contextCancelFunc = context.WithCancel(context.Background())
		peer.onNoControlStreamsLeftChan = make(chan struct{})
		peer.onNoForwarderStreamsLeftChan = make(chan struct{})
		peer.startChannelChan = make(chan ChannelType)
		peer.setIPFSForwarderStreamChan = make(chan Stream)
		peer.switchDirectChannelToPathOfChannelChan = make(chan ChannelType)
		peer.startCallChansHandler()
		peer.startPinger()
	})
}

func (peer *Peer) startCallChansHandler() {
	go peer.callChansHandlerLoop()
}

func (peer *Peer) startPinger() {
	go peer.pingerLoop()
}

func (peer *Peer) isFinished() bool {
	select {
	case <-peer.context.Done():
		return true
	default:
		return false
	}
}

func (peer *Peer) callChansHandlerLoop() {
	peer.VPN.logger.Debugf(`peer<%v>.callChansHandlerLoop()`, peer.ID)
	defer peer.VPN.logger.Debugf(`/peer<%v>.callChansHandlerLoop()`, peer.ID)
	for {
		peer.VPN.logger.Debugf(`peer<%v>.callChansHandlerLoop(): waiting...`, peer.ID)

		var fn func() error
		select {
		case <-peer.context.Done():
			return
		case <-peer.onNoControlStreamsLeftChan:
			fn = func() error {
				peer.onNoControlStreamsLeft()
				time.Sleep(time.Second)
				return nil
			}
		case <-peer.onNoForwarderStreamsLeftChan:
			fn = func() error {
				peer.onNoForwarderStreamsLeft()
				time.Sleep(time.Second)
				return nil
			}
		case chType := <-peer.startChannelChan:
			fn = func() error { return peer.startChannel(chType) }
		case stream := <-peer.setIPFSForwarderStreamChan:
			fn = func() error { return peer.setIPFSForwarderStream(stream) }
		case chType := <-peer.switchDirectChannelToPathOfChannelChan:
			fn = func() error {
				peer.switchDirectChannelToPathOfChannel(chType)
				return nil
			}
		}
		if peer.isFinished() {
			return
		}
		peer.VPN.logger.Debugf(`peer<%v>.callChansHandlerLoop(): received an event...`, peer.ID)
		err := fn()
		if err != nil {
			peer.VPN.logger.Error(err)
		}
	}
}

func (peer *Peer) pingerLoop() {
	tickerIPFS := time.NewTicker(time.Second * 10)
	defer tickerIPFS.Stop()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	if IsDisabledChannel(ChannelTypeIPFS) {
		tickerIPFS.Stop()
	}

	peer.LastSuccessfulPingTS.Store(time.Now())
	peer.LastSuccessfulIPFSPingTS.Store(time.Now())

	for {
		select {
		case <-peer.context.Done():
			return
		case <-tickerIPFS.C:
			go func() {
				prevLastSuccessfulPingTS := peer.LastSuccessfulIPFSPingTS.Load().(time.Time)

				for i := 0; i < 5; i++ {
					if err := peer.SendPing(ChannelTypeIPFS); err != nil {
						peer.VPN.logger.Error(errors.Wrap(err))
					}
					time.Sleep(time.Second)
					if peer.LastSuccessfulIPFSPingTS.Load().(time.Time) != prevLastSuccessfulPingTS {
						return
					}
				}

				peer.VPN.logger.Error(`peer `, peer.ID, ` timed-out on IPFS`)
				_ = peer.CloseIPFS()
			}()
		case <-ticker.C:
			prevLastSuccessfulPingTS := peer.LastSuccessfulPingTS.Load().(time.Time)

			func() {
				for i := 0; i < 300; i++ {
					for _, chType := range []ChannelType{ChannelTypeIPFS, ChannelTypeDirect, ChannelTypeTunnel} {
						if IsDisabledChannel(chType) {
							continue
						}
						go func(chType ChannelType) {
							if err := peer.SendPing(chType); err != nil {
								peer.VPN.logger.Error(errors.Wrap(err))
							}
						}(chType)
					}
					time.Sleep(time.Second)
					if peer.LastSuccessfulPingTS.Load().(time.Time) != prevLastSuccessfulPingTS {
						return
					}
				}
				peer.VPN.logger.Error(`peer `, peer.ID, ` completely timed-out`)
				_ = peer.Close()
			}()
		}
	}
}

func (peer *Peer) CloseIPFS() (err error) {
	peer.LockDo(func() {
		err = peer.closeIPFS()
	})
	return
}

func (peer *Peer) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.Close()`, peer.ID)

	select {
	case <-peer.context.Done():
		return ErrAlreadyClosed
	default:
	}
	peer.contextCancelFunc()

	peer.LockDo(func() {
		err = peer.cleanup()
	})
	return
}

func (peer *Peer) closeIPFS() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.closeIPFS()`, peer.ID)

	if peer.IPFSControlStream != nil {
		err = peer.IPFSControlStream.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
	}

	if peer.IPFSForwarderStream != nil {
		err = peer.IPFSForwarderStream.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
	}

	if peer.IPFSTunnelConnToWG != nil {
		err = peer.IPFSTunnelConnToWG.Close()
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
		}
		peer.IPFSTunnelConnToWG = nil
	}

	return nil
}

func (peer *Peer) cleanup() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.cleanup()`, peer.ID)

	if peer.onNoControlStreamsLeftChan != nil {
		close(peer.onNoControlStreamsLeftChan)
		peer.onNoControlStreamsLeftChan = nil
	}

	if peer.onNoForwarderStreamsLeftChan != nil {
		close(peer.onNoForwarderStreamsLeftChan)
		peer.onNoForwarderStreamsLeftChan = nil
	}

	if peer.startChannelChan != nil {
		close(peer.startChannelChan)
		peer.startChannelChan = nil
	}

	if peer.setIPFSForwarderStreamChan != nil {
		close(peer.setIPFSForwarderStreamChan)
		peer.setIPFSForwarderStreamChan = nil
	}

	if peer.switchDirectChannelToPathOfChannelChan != nil {
		close(peer.switchDirectChannelToPathOfChannelChan)
		peer.switchDirectChannelToPathOfChannelChan = nil
	}

	err = peer.closeIPFS()
	if err != nil {
		return
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

	peer.VPN.mesh.ClosePeer(peer.GetID())
	return
}

func (peer *Peer) configureDevice(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

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

	if peer.VPN.wgnets[chType].IfaceName == "" {
		panic(fmt.Errorf("empty device name for channel '%v'", chType))
	}

	peer.VPN.logger.Debugf(`configuring device %v for channel %v of peer %v with config %v`,
		peer.VPN.wgnets[chType].IfaceName,
		chType,
		peer.ID,
		wgCfg,
	)
	err = peer.VPN.wgctl.ConfigureDevice(peer.VPN.wgnets[chType].IfaceName, wgCfg)
	if err != nil {
		return
	}

	return
}

func (peer *Peer) onNoControlStreamsLeft() {
	vpn := peer.VPN

	vpn.logger.Debugf("no control streams left, peer.ID == %v", peer.ID)
	defer vpn.logger.Debugf("endof: no control streams left, peer.ID == %v", peer.ID)

	if peer.GetIPFSControlStream() != nil {
		vpn.logger.Debugf(`peer<%v>.onNoControlStreamsLeft(): false alarm`, peer.ID)
		return
	}

	isIncoming := peer.VPN.mesh.IsIncomingStream(peer.ID)
	if isIncoming == nil {
		vpn.logger.Error(`peer<`, peer.ID, `>.onNoControlStreamsLeft(): the stream does not exist.`)
		_ = peer.CloseIPFS()
		return
	}
	if *isIncoming {
		vpn.logger.Debugf(`peer<%v>.onNoControlStreamsLeft(): to do not duplicate connections we will wait for an incoming connection`, peer.ID)
		return
	}

	outgoingStream := helpers.NewReconnectableStream(vpn.logger, func() (Stream, error) {
		return vpn.mesh.NewStream(peer.ID, vpn.ProtocolID()+`/control/`+protocol.ID(vpn.myID.String()))
	})

	outgoingStream.Connect()
	if outgoingStream.Stream == nil {
		vpn.logger.Infof(`onNoControlStreamsLeft(): unable to connect to %v`, peer.ID)
		return
	}

	vpn.logger.Debugf(`New outgoing control stream for peer %v`, peer.ID)

	err := peer.SetIPFSControlStream(outgoingStream)
	if err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err := outgoingStream.Close()
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			return
		}
	}
}

func (peer *Peer) GetIPFSForwarderStream() (result Stream) {
	peer.VPN.logger.Debugf(`GetIPFSForwarderStream`)
	defer peer.VPN.logger.Debugf(`/GetIPFSForwarderStream`)

	peer.RLockDo(func() {
		result = peer.IPFSForwarderStream
	})

	return
}

func (peer *Peer) onNoForwarderStreamsLeft() {
	vpn := peer.VPN

	vpn.logger.Debugf("no forwarder streams left, peer.ID == %v", peer.ID)

	if peer.GetIPFSForwarderStream() != nil {
		vpn.logger.Debugf(`peer<%v>.onNoForwarderStreamsLeft(): false alarm`, peer.ID)
		return
	}

	if IsDisabledChannel(ChannelTypeIPFS) {
		vpn.logger.Debugf(`peer<%v>.onNoForwarderStreamsLeft(): but IPFS forwarders are disabled, so ignoring`, peer.ID)
		return
	}

	isIncoming := peer.VPN.mesh.IsIncomingStream(peer.ID)
	if isIncoming == nil {
		vpn.logger.Error(`peer<`, peer.ID, `>.onNoControlStreamsLeft(): the stream does not exist.`)
		_ = peer.CloseIPFS()
		return
	}
	if *isIncoming {
		vpn.logger.Debugf(`peer<%v>.onNoForwarderStreamsLeft(): to do not duplicate connections we will wait for an incoming connection`, peer.ID)
		return
	}

	go func() {
		concurrency := atomic.AddInt32(&peer.onNoForwarderStreamsLeftConcurrency, 1)
		defer atomic.AddInt32(&peer.onNoForwarderStreamsLeftConcurrency, -1)
		if concurrency > 1 {
			vpn.logger.Debugf(`peer<%v>.onNoForwarderStreamsLeft(): is already running`, peer.ID)
			if len(peer.onNoForwarderStreamsLeftChan) == 0 && concurrency == 2 {
				vpn.logger.Debugf(`peer<%v>.onNoForwarderStreamsLeft(): is already running -> pending`, peer.ID)
				go func() {
					defer peer.recover()
					peer.onNoForwarderStreamsLeftChan <- struct{}{}
				}()
			}
			return
		}
		outgoingStream := helpers.NewReconnectableStream(vpn.logger, func() (Stream, error) {
			return vpn.mesh.NewStream(peer.ID, vpn.ProtocolID()+`/wg/`+protocol.ID(vpn.myID.String()))
		})

		outgoingStream.Connect()
		if outgoingStream.Stream == nil {
			vpn.logger.Infof(`Lost the IPFS connection to %v`, peer.ID)
			return
		}

		vpn.logger.Debugf(`A new outgoing traffic forward stream for peer %v`, peer.ID)

		peer.addTunnelConnection(outgoingStream, AddrInfo{ID: peer.ID})
	}()
}

func (peer *Peer) SwitchDirectChannelToPathOfChannel(chType ChannelType) {
	go func() {
		peer.VPN.logger.Debugf(`peer<%v>.SwitchDirectChannelToPathOfChannel(%v)`, peer.ID, chType)

		var ch chan ChannelType
		peer.RLockDo(func() {
			ch = peer.switchDirectChannelToPathOfChannelChan
		})
		ch <- chType
	}()
}

func (peer *Peer) switchDirectChannelToPathOfChannel(chType ChannelType) {
	vpn := peer.VPN
	peer.VPN.logger.Debugf(`peer<%v>.switchDirectChannelToPathOfChannel(%v)`, peer.ID, chType)
	defer peer.VPN.logger.Debugf(`/peer<%v>.switchDirectChannelToPathOfChannel(%v)`, peer.ID, chType)

	newDirectIP := peer.GetRemoteRealIP(chType)
	peer.VPN.logger.Debugf(`peer<%v>.switchDirectChannelToPathOfChannel(%v): %v %v`, peer.ID, chType, peer.DirectAddr, newDirectIP)
	if peer.DirectAddr != nil && peer.DirectAddr.IP.String() == newDirectIP.String() {
		return
	}

	port := vpn.getPeerPort(peer.ID, ChannelTypeDirect)
	vpn.logger.Debugf(`peer<%v>.switchDirectChannelToPathOfChannel(%v): vpn.getPeerPort("%v", ChannelTypeDirect) -> %v`, peer.ID, chType, peer.ID, port)
	if port == 0 {
		return
	}

	newDirectAddr := &net.UDPAddr{
		IP:   newDirectIP,
		Port: int(port),
	}
	peer.LockDo(func() {
		peer.DirectAddr = newDirectAddr
	})

	peer.StartChannel(ChannelTypeDirect)
}

func (peer *Peer) sendIntAliases(conn io.Writer) (err error) {
	vpn := peer.VPN
	vpn.logger.Debugf("sendIntAliases()")
	defer func() { vpn.logger.Debugf("/sendIntAliases(): err == %v", err) }()

	defer func() { err = errors.Wrap(err) }()

	knownAliases := IntAliases{vpn.GetIntAlias().Copy()}
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		if peer.IntAlias.PeerID.String() == "" {
			return true
		}
		knownAliases = append(knownAliases, peer.IntAlias.Copy())
		return true
	})
	for _, intAlias := range knownAliases {
		intAlias.Since = time.Since(intAlias.Timestamp)
		intAlias.Timestamp = time.Time{}
	}

	b := make([]byte, sizeOfMessageType+sizeOfMessageIntAlias)
	vpn.logger.Debugf(`len(b) == %v (expected %v + %v)`, len(b), sizeOfMessageType, sizeOfMessageIntAlias)
	MessageTypeIntAlias.Write(b)
	for idx, intAlias := range knownAliases {
		vpn.logger.Debugf(`%d: %#+v`, idx, intAlias)
		if intAlias.Value == 0 {
			panic("intAlias.Value == 0")
		}
		if intAlias.PeerID == "" {
			panic("zero peer ID")
		}
		msg := &MessageIntAlias{
			Index: int32(idx),
			Count: int32(len(knownAliases)),
		}
		err = msg.FillFrom(intAlias)
		if err != nil {
			return errors.Errorf("unable to fill message from IntAlias: %w", err)
		}
		if msg.Value == 0 {
			panic("msg.Value == 0")
		}
		if bytesextra.IsZeroFilled(msg.PeerID[:]) {
			panic("zero peer ID")
		}
		msg.Write(b[sizeOfMessageType:])

		var n int
		n, err = conn.Write(b)
		vpn.logger.Debugf("sendIntAlias(): stream.Write(): %v %v %v", n, err, string(b))
		if err != nil {
			return
		}
		if n != len(b) {
			err = ErrMessageFragmented
			return
		}
	}

	return
}

func (peer *Peer) recvIntAliases(conn io.ReadCloser) (remoteIntAliases IntAliases, err error) {
	defer func() { err = errors.Wrap(err, fmt.Errorf("%T", err)) }()
	vpn := peer.VPN

	vpn.logger.Debugf("recvIntAlias(): peer ID %v", peer.ID)
	defer vpn.logger.Debugf("/recvIntAlias(): peer ID %v", peer.ID)

	buf := make([]byte, sizeOfMessageType+sizeOfMessageIntAlias)

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	go func() {
		timer := time.NewTimer(receiveIntAliasesTimeout)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			peer.VPN.logger.Error(`recvIntAlias(): timed-out while waiting for int aliases from the remote side`)
			conn.Close()
		}
	}()

	defer func() {
		if len(remoteIntAliases) == 0 {
			err = errors.New("empty slice")
		}
	}()

	var count, expectedCount int
	for expectedCount == 0 || count < expectedCount {
		var n int
		vpn.logger.Debugf("recvIntAlias(): stream.Read()... %v/%v", count, expectedCount)
		n, err = conn.Read(buf)
		vpn.logger.Debugf("recvIntAlias(): stream.Read(): %v %v %v", n, err, string(buf[:n]))
		if n >= bufferSize {
			return nil, errors.New("too big message")
		}
		if err != nil {
			return
		}

		if n != sizeOfMessageType+sizeOfMessageIntAlias {
			err = errors.Wrap(ErrWrongMessageLength, n)
			return
		}

		msgType := ReadMessageType(buf)
		vpn.logger.Debugf(`recvIntAlias(): msgType == %v`, msgType)
		if msgType != MessageTypeIntAlias {
			continue
		}

		intAliasMessage := &MessageIntAlias{}
		err = intAliasMessage.Read(buf[sizeOfMessageType:n])
		vpn.logger.Debugf(`recvIntAlias(): intAliasMessage: %v %v`, err, intAliasMessage)
		if err != nil {
			return
		}

		if expectedCount == 0 {
			expectedCount = int(intAliasMessage.Count)
			remoteIntAliases = make(IntAliases, expectedCount)
		}
		if expectedCount != int(intAliasMessage.Count) {
			err = errors.Wrap(ErrUnexpectedCount, expectedCount, intAliasMessage.Count)
			return
		}

		if remoteIntAliases[intAliasMessage.Index] != nil {
			continue
		}

		var intAlias *IntAlias
		{
			intAlias = &IntAlias{}
			remoteIntAliases[intAliasMessage.Index] = intAlias
		}

		err = intAliasMessage.FillTo(intAlias)
		if err != nil {
			return
		}

		count++
	}

	return
}

func (peer *Peer) NewIncomingStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn := peer.VPN

	switch {
	case strings.HasPrefix(string(stream.Protocol()), string(vpn.ProtocolID()+`/wg/`)):
		vpn.logger.Debugf(`newIncomingStream: wg for %v`, peerAddr.ID)
		if !IsDisabledChannel(ChannelTypeIPFS) {
			vpn.logger.Debugf(`newIncomingStream: wg for %v: addTunnelConnection`, peerAddr.ID)
			go peer.addTunnelConnection(stream, peerAddr)
		}
		return
	case strings.HasPrefix(string(stream.Protocol()), string(vpn.ProtocolID()+`/control/`)):
		vpn.logger.Debugf(`newIncomingStream: control for %v`, peerAddr.ID)
		return peer.SetIPFSControlStream(stream)
	}

	panic(`should not happen`)
}

func (peer *Peer) negotiate_withLock(conn io.ReadWriteCloser) (remoteIntAlias IntAlias, err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn := peer.VPN
	vpn.logger.Debugf("negotiate_withLock(%T)", conn)
	defer func() { vpn.logger.Debugf("/negotiate_withLock(%T) -> %#+v, %v", conn, remoteIntAlias, err) }()

	myIntAlias := vpn.GetIntAlias()

	peer.locker.RLock()
	defer peer.locker.RUnlock()

	err = peer.sendIntAliases(conn)
	if err != nil {
		return
	}

	peer.locker.RUnlock()
	remoteIntAliases, err := peer.recvIntAliases(conn)
	peer.locker.RLock()
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
		if remoteIntAlias.PeerID == myIntAlias.PeerID {
			continue
		}
		remoteIntAlias.Timestamp = time.Now().Add(-remoteIntAlias.Since)
		notMyIntAliases[remoteIntAlias.Value] = remoteIntAlias
	}
	if remoteIntAliases[0].Value == myIntAlias.Value {
		changeOnRemoteSide := false
		if myIntAlias.MaxNetworkSize > remoteIntAliases[0].MaxNetworkSize {
			changeOnRemoteSide = true
		} else if myIntAlias.MaxNetworkSize == remoteIntAliases[0].MaxNetworkSize {
			if myIntAlias.Timestamp.UnixNano() > remoteIntAliases[0].Timestamp.UnixNano() {
				changeOnRemoteSide = true
			} else if myIntAlias.Timestamp.UnixNano() == remoteIntAliases[0].Timestamp.UnixNano() {
				if vpn.myID < peer.ID {
					changeOnRemoteSide = true
				}
			}
		}

		if changeOnRemoteSide {
			vpn.logger.Debugf("int alias collision, remote side should change it's alias %v <?= %v , %v <?= %v, %v >? %v",
				myIntAlias.Value, remoteIntAliases[0].Value,
				myIntAlias.Timestamp, remoteIntAliases[0].Timestamp,
				vpn.myID, peer.ID)

			err = peer.sendIntAliases(conn)
			if err != nil {
				return
			}
			peer.locker.RUnlock()
			remoteIntAliases, err = peer.recvIntAliases(conn)
			peer.locker.RLock()
			if err != nil {
				return
			}
			if remoteIntAliases[0].Value == myIntAlias.Value {
				err = errors.New("remote side decided not to change it's int alias, close connection")
				return
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
					myIntAlias = vpn.GetIntAlias()
					break
				}
			}
			err = peer.sendIntAliases(conn)
			if err != nil {
				return
			}
			peer.locker.RUnlock()
			_, err = peer.recvIntAliases(conn)
			peer.locker.RLock()
			if err != nil {
				return
			}

			warnErr := vpn.SaveConfig()
			if warnErr != nil {
				vpn.logger.Error(errors.Wrap(err))
			}
		}
	}

	remoteIntAlias = *remoteIntAliases[0]
	remoteIntAlias.Timestamp = time.Now().Add(-remoteIntAlias.Since)

	vpn.logger.Debugf("negotiations with %v are complete: my_alias:%d, remote_alias:%d", peer.ID, vpn.GetIntAlias().Value, remoteIntAlias.Value)

	// Just in case, if a packet was lost
	_ = peer.sendIntAliases(conn)

	return
}

func (peer *Peer) SetIntAlias(newIntAlias IntAlias) {
	peer.LockDo(func() {
		peer.IntAlias = newIntAlias
	})
}

func (peer *Peer) setupTunnelConnection(conn io.ReadWriteCloser, peerAddr AddrInfo, remoteIntAlias IntAlias) (chType ChannelType) {
	vpn := peer.VPN
	vpn.logger.Debugf("setupTunnelConnection(%T, %v, %v)", conn, peerAddr.ID, remoteIntAlias.Value)
	defer func() {
		vpn.logger.Debugf("/setupTunnelConnection(%T, %v, %v) -> %v", conn, peerAddr.ID, remoteIntAlias.Value, chType)
	}()

	peer.SetIntAlias(remoteIntAlias)

	switch connTyped := conn.(type) {
	case *helpers.ReconnectableStream:
		chType = ChannelTypeIPFS
		peer.SetIPFSForwarderStream(connTyped, true)
	case Stream:
		chType = ChannelTypeIPFS
		peer.SetIPFSForwarderStream(connTyped, false)
	case *udpWriter:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		peer.SetSimpleTunnelConn(connTyped)
	case *net.UDPConn:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		peer.SetSimpleTunnelConn(connTyped)
	case *udpClientSocket:
		vpn.cancelPingSenderLoop(peerAddr.ID)
		chType = ChannelTypeTunnel
		peer.SetSimpleTunnelConn(connTyped)
	}

	return
}

func (peer *Peer) addTunnelConnection(conn io.ReadWriteCloser, peerAddr AddrInfo) {
	vpn := peer.VPN
	vpn.logger.Debugf("new tunnel connection to %v (%T)", peer.ID, conn)

	remoteIntAlias, err := peer.negotiate_withLock(conn)
	if err != nil {
		return
	}
	chType := peer.setupTunnelConnection(conn, peerAddr, remoteIntAlias)
	if IsDisabledChannel(chType) {
		panic(fmt.Errorf("should not even reach this code: %v", chType))
	}

	vpn.logger.Debugf("peer.StartChannel(%v)", chType)

	peer.StartChannel(chType)

	go func() {
		saveErr := vpn.SaveConfig()
		if saveErr != nil {
			vpn.logger.Error(saveErr)
		}
	}()

	vpn.logger.Debugf("finished to setup on a new tunnel connection to %v", peer.ID)
}

func (peer *Peer) startControlStream() (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.startControlStream()`, peer.ID)
	defer peer.VPN.logger.Debugf(`endof peer<%v>.startControlStream()`, peer.ID)

	go peer.LockDo(func() {
		if peer.IPFSControlStream == nil || peer.controlStreamTunnelReaderRunning {
			return
		}
		peer.VPN.logger.Debugf(`peer<%v>.startControlStream(): starting stream reader`, peer.ID)
		peer.controlStreamTunnelReaderRunning = true

		go func(stream Stream) {
			peer.controlStreamReaderLoop(stream)
			peer.VPN.logger.Debugf(`endof peer<%v>.controlStreamReaderLoop(peer.IPFSControlStream)`, peer.ID)
			peer.LockDo(func() {
				peer.controlStreamTunnelReaderRunning = false
				if peer.IPFSControlStream != stream {
					return
				}

				peer.VPN.logger.Debugf(`peer<%v>.IPFSControlStream = nil`, peer.ID)
				_ = peer.IPFSControlStream.Close()
				peer.IPFSControlStream = nil
				go func() {
					defer peer.recover()
					peer.onNoControlStreamsLeftChan <- struct{}{}
				}()
			})
		}(peer.IPFSControlStream)
	})

	return
}

func (peer *Peer) recover() {
	err := recover()
	if err == nil {
		return
	}

	peer.VPN.logger.Debugf(`peer<%v>.recover() -> %v`, peer.ID, err)
}

func (peer *Peer) StartChannel(chType ChannelType) {
	go func() {
		defer peer.recover()
		peer.startChannelChan <- chType
	}()
}

// Should be called only inside LockDo
func (peer *Peer) lazyInitTunnelConnToWG(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.lazyInitTunnelConnToWG(%v)`, peer.ID, chType)
	defer func() { peer.VPN.logger.Debugf(`/peer<%v>.lazyInitTunnelConnToWG(%v) -> %v`, peer.ID, chType, err) }()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSTunnelConnToWG != nil {
			return
		}
		peer.IPFSTunnelConnToWG, peer.IPFSTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
			IP:   net.ParseIP(`127.0.0.1`),
			Port: 0, // automatically assign a free port
		})
	case ChannelTypeTunnel:
		if peer.SimpleTunnelConnToWG != nil {
			return
		}
		peer.SimpleTunnelConnToWG, peer.SimpleTunnelAddrToWG, err = newUDPListener(&net.UDPAddr{
			IP:   net.ParseIP(`127.0.0.1`),
			Port: 0, // automatically assign a free port
		})
		if peer.SimpleTunnelConnToWG == nil {
			panic("peer.SimpleTunnelConnToWG == nil")
		}
	default:
		panic(errors.Errorf("unexpected channel type: %v", chType))
	}

	return
}

func (peer *Peer) startChannel(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn := peer.VPN
	vpn.logger.Debugf("startChannel(%v)", chType)
	defer vpn.logger.Debugf("/startChannel(%v)", chType)

	if IsDisabledChannel(chType) {
		panic(errors.Errorf("should not happen: %v", chType))
	}

	if chType != ChannelTypeDirect {
		peer.LockDo(func() {
			err = peer.lazyInitTunnelConnToWG(chType)
			if err != nil {
				return
			}

			err = peer.startTunnelReader(chType)
			if err != nil {
				return
			}

			err = peer.startTunnelWriter(chType)
			if err != nil {
				return
			}
		})
	}

	err = peer.configureDevice(chType)
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

	defer func() { peer.VPN.logger.Debugf(`peer<%v>.replyWithPong -> %v`, peer.ID, err) }()

	recvTS := time.Now()

	var pong MessagePong
	if err = pong.MessagePing.Read(pingBytes); err != nil {
		return
	}

	if signErr := pong.MessagePing.VerifySender(peer.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof("invalid sender signature of an incoming ping message from peer %v (%v): %v %v: %v", peer.GetID(), peer.GetPublicKey(), pong.MessagePingData.Bytes(), pong.SenderSignature, signErr)
		return
	}

	pong.ReceiveTS = recvTS.UnixNano()
	privKey := peer.VPN.PrivKey()

	pong.SendTS = time.Now().UnixNano()
	if err = pong.SignRecipient(privKey); err != nil {
		return
	}

	var buf bytes.Buffer
	if err = binary.Write(&buf, binary.LittleEndian, MessageTypePong); err != nil {
		return
	}
	if err = pong.WriteTo(&buf); err != nil {
		return
	}

	if _, err = writer.Write(buf.Bytes()); err != nil {
		return
	}

	return
}

func (peer *Peer) considerRTT(chType ChannelType, rtt time.Duration) (err error) {
	defer func() { err = errors.Wrap(err) }()

	defer func() { peer.VPN.logger.Debugf(`peer<%v>.considerRTT(%v %v) -> %v`, peer.ID, chType, rtt, err) }()

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

	defer func() { peer.VPN.logger.Debugf(`peer<%v>.considerPong -> %v`, peer.ID, err) }()

	recvTS := time.Now()

	if signErr := pong.VerifySender(peer.VPN.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof(`invalid sender signature in a pong message from peer %v: %v`, peer.ID, signErr)
		return
	}

	if signErr := pong.VerifyRecipient(peer.GetPublicKey()); signErr != nil {
		peer.VPN.logger.Infof(`invalid recipient signature in a pong message from peer %v: %v`, peer.ID, signErr)
		return
	}

	peer.LastSuccessfulPingTS.Store(time.Now())
	if chType == ChannelTypeIPFS {
		peer.LastSuccessfulIPFSPingTS.Store(time.Now())
	}

	if err = peer.considerRTT(chType, recvTS.Sub(time.Unix(0, pong.MessagePing.SendTS))); err != nil {
		return
	}

	return
}

func (peer *Peer) considerPongBytes(pongBytes []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.considerPongBytes: %v`, peer.ID, len(pongBytes))

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
	peer.VPN.logger.Debugf("peer<%v>.forwardPacketToWG -> %v, %v", peer.ID, size, err)
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
		size, err := conn.Read(buffer[:2])
		if err != nil {
			if err == mux.ErrReset || err == io.EOF || err == mocknet.ErrClosed || err.Error() == "service conn reset" {
				peer.VPN.logger.Infof("[control] IPFS connection closed while reading headers (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
			} else {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		if size < 2 {
			peer.VPN.logger.Error(errors.Wrap(ErrMessageTooShort))
			return
		}

		msg := buffer[:2]
		msgType := MessageType(binary.LittleEndian.Uint16(msg))

		var expectedSize int
		switch msgType {
		case MessageTypePing:
			expectedSize = sizeOfMessagePing
		case MessageTypePong:
			expectedSize = sizeOfMessagePong
		default:
			err = errors.Wrap(ErrUnknownMessageType, msgType)
		}
		if err != nil {
			peer.VPN.logger.Error(errors.Wrap(err))
			err := peer.CloseIPFS()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		payload := buffer[:expectedSize]

		size, err = conn.Read(payload)
		if err != nil {
			if err == mux.ErrReset || err == io.EOF || err == mocknet.ErrClosed || err.Error() == "service conn reset" {
				peer.VPN.logger.Infof("[control] IPFS connection closed while reading the payload (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
			} else {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		if size < expectedSize {
			peer.VPN.logger.Error(errors.Wrap(ErrMessageTooShort))
			return
		}

		peer.VPN.logger.Debugf(`peer<%v>.controlStreamReaderLoop(): received a message (len: %v): %v %v`, peer.ID, size, msgType, payload)
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
			return
		}
	}
}

func (peer *Peer) tunnelToWgForwarderLoop(conn io.ReadWriteCloser) {
	logger := peer.VPN.logger
	logger.Debugf("peer<%v>.tunnelToWgForwarderLoop(%T)", peer.ID, conn)
	defer logger.Debugf("/peer<%v>.tunnelToWgForwarderLoop(%T)", peer.ID, conn)

	buffer := [peerBufferSize]byte{}

	for {
		size, err := conn.Read(buffer[:])
		logger.Debugf("peer<%v>.tunnelToWgForwarderLoop(%T) -> read: %d, %v", peer.ID, conn, size, err)
		if err != nil {
			if err == mux.ErrReset || err == io.EOF || err == mocknet.ErrClosed || err.Error() == "service conn reset" {
				logger.Infof("[tunnel] IPFS connection closed (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
			} else {
				logger.Error(errors.Wrap(err))
			}
			return
		}

		err = peer.forwardPacketToWG(buffer[:size], conn)
		logger.Debugf("peer<%v>.tunnelToWgForwarderLoop(%T) -> write: %v", peer.ID, conn, err)
		if err != nil {
			logger.Error(errors.Wrap(err))
			err := conn.Close()
			if err != nil {
				logger.Error(errors.Wrap(err))
			}
			return
		}
	}
}

// Should be called only inside LockDo
func (peer *Peer) startTunnelReader(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	logger := peer.VPN.logger
	logger.Debugf("peer<%v>.startTunnelReader", peer.ID)
	defer func() { logger.Debugf("/peer<%v>.startTunnelReader -> %v", peer.ID, err) }()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSTunnelConnToWG == nil {
			panic("peer.IPFSTunnelConnToWG == nil")
		}

		if peer.IPFSForwarderStream == nil || peer.forwarderStreamTunnelReaderRunning {
			return
		}
		peer.forwarderStreamTunnelReaderRunning = true
		go func(stream Stream) {
			conn := newUDPWriter(peer.IPFSTunnelConnToWG, stream, &peer.VPN.wgnets[chType].WGListenerAddr)
			peer.tunnelToWgForwarderLoop(conn)
			logger.Debugf(`endof peer<%v>.tunnelToWgForwarderLoop(conn)`, peer.ID)
			peer.LockDo(func() {
				peer.forwarderStreamTunnelReaderRunning = false
				if peer.IPFSForwarderStream != stream {
					return
				}
				logger.Debugf(`peer<%v>.IPFSForwarderStream = nil`, peer.ID)
				_ = peer.IPFSForwarderStream.Close()
				peer.IPFSForwarderStream = nil
				peer.VPN.ReconnectToPeer(peer.ID)
			})
		}(peer.IPFSForwarderStream)

	case ChannelTypeTunnel:
		if peer.SimpleTunnelConnToWG == nil {
			panic("peer.SimpleTunnelConnToWG == nil")
		}

		conn := newUDPWriter(peer.SimpleTunnelConnToWG, peer.SimpleTunnelConn, &peer.VPN.wgnets[chType].WGListenerAddr)
		go peer.tunnelToWgForwarderLoop(conn)

	default:
		panic(fmt.Errorf("invalid channel type: %v", chType))
	}

	return
}

func (peer *Peer) SendPing(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.SendPing(%v)...`, peer.ID, chType)

	switch chType {
	case ChannelTypeDirect, ChannelTypeTunnel:
		if peer.IntAlias.Value == 0 {
			peer.VPN.logger.Debugf(`peer<%v>.SendPing(%v): peer.IntAlias.Value == 0`, peer.ID, chType)
			return
		}
		var remoteVPNIP net.IP
		if remoteVPNIP, err = peer.VPN.GetIP(peer.IntAlias.Value, chType); err != nil {
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
		writer := peer.GetIPFSControlStream()
		if writer == nil {
			return ErrWriterIsNil
		}

		var ping MessagePing
		ping.SequenceID = 0
		ping.SendTS = time.Now().UnixNano()

		privKey := peer.VPN.PrivKey()
		if err = ping.SignSender(privKey); err != nil {
			return
		}
		peer.VPN.logger.Debugf(`peer<%v>.SendPing(%v): signature: %v %v %v`, peer.ID, chType, privKey.Public(), ping.MessagePingData.Bytes(), ping.SenderSignature)
		var buf bytes.Buffer
		if err = binary.Write(&buf, binary.LittleEndian, MessageTypePing); err != nil {
			return
		}
		if err = ping.WriteTo(&buf); err != nil {
			return
		}

		msg := buf.Bytes()
		if _, err = writer.Write(msg); err != nil {
			return
		}
		peer.VPN.logger.Debugf(`peer<%v>.SendPing(%v): sent: %v`, peer.ID, chType, msg)
	default:
		panic(fmt.Errorf(`shouldn't happened: %v`, chType))
	}
	return
}

func (peer *Peer) GetRemoteRealIP(chType ChannelType) (result net.IP) {
	peer.RLockDo(func() {
		result = peer.getRemoteRealIP(chType)
	})
	return
}

func (peer *Peer) getRemoteRealIP(chType ChannelType) (result net.IP) {
	switch chType {
	case ChannelTypeDirect:
		if peer.DirectAddr == nil {
			return nil
		}
		return peer.DirectAddr.IP
	case ChannelTypeIPFS:
		ipfsStream := peer.GetIPFSControlStream()
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
		remoteAddr := peer.SimpleTunnelConn.RemoteAddr()
		if remoteAddr == nil {
			if remoteAddr == nil {
				panic("remoteAddr == nil")
			}
		}
		return net.ParseIP(strings.Split(remoteAddr.String(), `:`)[0])
	}

	panic(fmt.Errorf(`shouldn't happened: %v'`, chType))
	return nil
}

func (peer *Peer) GetOptimalChannel(chTypes ...ChannelType) (optimalChannelType ChannelType) {
	optimalChannelType = ChannelType_undefined
	minRTT := time.Duration(5 * time.Second)

	for _, chType := range chTypes {
		stats := &peer.channelStatistics[chType]
		peer.VPN.logger.Debugf(`peer<%v>.GetOptimalChannel(%v): %v: check: %v %v %v`, peer.ID, chTypes, chType, stats.RTT, minRTT, stats.SamplesCount)

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

func (peer *Peer) wgToTunnelForwarderLoop(wgConn io.ReadCloser, tunnelConn io.Writer) {
	peer.VPN.logger.Debugf(`peer<%v>.wgToTunnelForwarderLoop(%T, %T)`, peer.ID, wgConn, tunnelConn)
	defer func() {
		peer.VPN.logger.Debugf(`/peer<%v>.wgToTunnelForwarderLoop(%T, %T)`, peer.ID, wgConn, tunnelConn)
	}()
	buffer := [peerBufferSize]byte{}

	for {
		size, err := wgConn.Read(buffer[:])
		peer.VPN.logger.Debugf(`peer<%v>.wgToTunnelForwarderLoop(%T, %T) -> read: %d, %v`, peer.ID, wgConn, tunnelConn, size, err)
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == io.EOF || netErr.Err.Error() == "use of closed network connection" {
					peer.VPN.logger.Infof("tunnel connection closed (peer ID %v:%v)", peer.IntAlias.Value, peer.GetID())
					return
				}
			}
			peer.VPN.logger.Error(errors.Wrap(err))
			err := wgConn.Close()
			if err != nil {
				peer.VPN.logger.Error(errors.Wrap(err))
			}
			return
		}

		wSize, err := tunnelConn.Write(buffer[:size])
		peer.VPN.logger.Debugf(`peer<%v>.wgToTunnelForwarderLoop(%T, %T) -> write %d, %v`, peer.ID, wgConn, tunnelConn, wSize, err)
		if size != wSize {
			peer.VPN.logger.Error(errors.Wrap(ErrInvalidSize, size, wSize))
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
	var port int64
	port, err = strconv.ParseInt(addrString[strings.LastIndex(addrString, `:`)+1:], 10, 64)
	if err != nil {
		_ = conn.Close()
		return
	}
	addr.Port = int(port)

	return
}

func (peer *Peer) stopIPFSForwarderStream() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if peer.IPFSForwarderStream == nil {
		return
	}
	_ = peer.IPFSForwarderStream.Close()
	peer.IPFSForwarderStream = nil

	return
}

func (peer *Peer) stopIPFSControlStream() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if peer.IPFSControlStream == nil {
		return
	}
	_ = peer.IPFSControlStream.Close()
	peer.IPFSControlStream = nil

	return
}

func (peer *Peer) GetIPFSControlStream() (result Stream) {
	peer.VPN.logger.Debugf(`GetIPFSControlStream`)
	defer peer.VPN.logger.Debugf(`/GetIPFSControlStream`)

	peer.RLockDo(func() {
		result = peer.IPFSControlStream
	})

	return
}

func (peer *Peer) SetIPFSControlStream(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	conn := stream.Conn()
	if conn == nil {
		peer.VPN.logger.Debugf(`peer<%v>.SetIPFSControlStream(stream): conn == nil`, peer.ID)
		peer.VPN.ReconnectToPeer(peer.ID)
		return nil
	}

	peer.VPN.logger.Debugf(`peer<%v>.SetIPFSControlStream("%v")`, peer.ID, conn.RemotePeer())
	defer peer.VPN.logger.Debugf(`endof peer<%v>.SetIPFSControlStream("%v")`, peer.ID, conn.RemotePeer())

	peer.LockDo(func() {
		_ = peer.stopIPFSControlStream()
		peer.IPFSControlStream = stream
	})

	peer.VPN.logger.Debugf("calling peer.startControlStream()")

	err = peer.startControlStream()
	if err != nil {
		return
	}

	return
}

func (peer *Peer) SetIPFSForwarderStream(stream Stream, isOutgoing bool) {
	go func() {
		defer peer.recover()
		peer.VPN.logger.Debugf(`peer<%v>.SetIPFSForwarderStream("%v", %v)`, peer.ID, stream.Conn().RemotePeer(), isOutgoing)
		peer.setIPFSForwarderStreamChan <- struct {
			Stream
			bool
		}{stream, isOutgoing}
	}()
}

func (peer *Peer) setIPFSForwarderStream(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.setIPFSForwarderStream("%v")`, peer.ID, stream.Conn().RemotePeer())
	defer peer.VPN.logger.Debugf(`endof peer<%v>.setIPFSForwarderStream("%v")`, peer.ID, stream.Conn().RemotePeer())

	peer.LockDo(func() {
		_ = peer.stopIPFSForwarderStream()
		peer.IPFSForwarderStream = stream
	})

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

func (peer *Peer) SetSimpleTunnelConn(conn net.Conn) {
	peer.LockDo(func() {
		_ = peer.stopSimpleTunnelConn()
		peer.SimpleTunnelConn = conn
	})
}

// Should be called only inside LockDo
func (peer *Peer) startTunnelWriter(chType ChannelType) (err error) {
	defer func() { err = errors.Wrap(err) }()

	peer.VPN.logger.Debugf(`peer<%v>.startTunnelWriter(%v)`, peer.ID, chType)
	defer func() { peer.VPN.logger.Debugf(`/peer<%v>.startTunnelWriter(%v) -> %v`, peer.ID, chType, err) }()

	switch chType {
	case ChannelTypeIPFS:
		if peer.IPFSTunnelConnToWG == nil {
			panic("peer.IPFSTunnelConnToWG == nil")
		}

		if peer.IPFSForwarderStream == nil || peer.forwarderStreamTunnelWriterRunning {
			return
		}
		peer.forwarderStreamTunnelWriterRunning = true
		go func(connToWG net.Conn, stream Stream) {
			peer.wgToTunnelForwarderLoop(connToWG, stream)
			peer.LockDo(func() {
				peer.forwarderStreamTunnelWriterRunning = false
				if peer.IPFSForwarderStream != stream {
					peer.VPN.logger.Debugf("peer<%v>.IPFSForwarderStream != stream", peer.ID)
					return
				}
				peer.VPN.logger.Debugf(`peer<%v>.IPFSForwarderStream = nil`, peer.ID)
				_ = peer.IPFSForwarderStream.Close()
				peer.IPFSForwarderStream = nil
				peer.VPN.ReconnectToPeer(peer.ID)
			})
		}(peer.IPFSTunnelConnToWG, peer.IPFSForwarderStream)

	case ChannelTypeTunnel:
		if peer.SimpleTunnelConnToWG == nil {
			panic("peer.SimpleTunnelConnToWG == nil")
		}

		go peer.wgToTunnelForwarderLoop(peer.SimpleTunnelConnToWG, peer.SimpleTunnelConn)
	}

	return
}

func (peers Peers) ToWireGuardConfigs(chType ChannelType) (result []wgtypes.PeerConfig, err error) {
	defer func() { err = errors.Wrap(err) }()

	for _, peer := range peers {
		var peerCfg wgtypes.PeerConfig
		peer.LockDo(func() {
			peerCfg, err = peer.toWireGuardConfig(chType)
		})
		if err != nil {
			return nil, err
		}
		result = append(result, peerCfg)
	}
	return
}
