package vpn

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	simpleTunnelReaderQueueLength = 1024
)

type simpleTunnelReaderQueueItem struct {
	isBusy     bool
	conn       *net.UDPConn
	addrRemote *net.UDPAddr
	msg        []byte
}

var (
	simpleTunnelReaderQueueItemPool = sync.Pool{
		New: func() interface{} {
			return &simpleTunnelReaderQueueItem{}
		},
	}
)

func acquireSimpleTunnelReaderQueueItem(msgSize uint) *simpleTunnelReaderQueueItem {
	item := simpleTunnelReaderQueueItemPool.Get().(*simpleTunnelReaderQueueItem)
	if item.isBusy {
		panic(`should not happened`)
	}
	item.isBusy = true
	if cap(item.msg) < int(msgSize) {
		item.msg = make([]byte, msgSize)
	} else {
		item.msg = item.msg[:msgSize]
	}
	return item
}

func (item *simpleTunnelReaderQueueItem) Release() {
	if !item.isBusy {
		panic(`should not happened`)
	}
	item.isBusy = false
	simpleTunnelReaderQueueItemPool.Put(item)
}

type simpleTunnelReader struct {
	vpn                           *VPN
	peerAddrRemote                AddrInfo
	publicKeyRemote               ed25519.PublicKey
	gcFunc                        func() error
	addrs                         []*net.UDPAddr
	lastUseTS                     int64
	connectionInitContext         context.Context
	connectionInitContextStopFunc context.CancelFunc
	createTS                      time.Time
	queue                         chan *simpleTunnelReaderQueueItem
	messagePong                   MessagePong
	mySideIsReady                 bool
	remoteSideIsReady             bool
}

func newSimpleTunnelReader(vpn *VPN, peerAddrRemote AddrInfo, addrs []*net.UDPAddr, gcFunc func() error) (reader *simpleTunnelReader, err error) {
	defer func() { err = errors.Wrap(err) }()

	reader = &simpleTunnelReader{
		vpn:            vpn,
		peerAddrRemote: peerAddrRemote,
		addrs:          addrs,
		createTS:       time.Now(),
		gcFunc:         gcFunc,
		queue:          make(chan *simpleTunnelReaderQueueItem, simpleTunnelReaderQueueLength),
	}

	reader.publicKeyRemote, err = getPublicKeyFromPeerID(peerAddrRemote.ID)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	reader.start()
	return
}

func (r *simpleTunnelReader) HasAddress(addr *net.UDPAddr) bool {
	for _, cmpAddr := range r.addrs {
		if cmpAddr.Port == addr.Port && cmpAddr.IP.Equal(addr.IP) {
			return true
		}
	}
	return false
}

func (r *simpleTunnelReader) Close() error {
	err := r.gcFunc()
	r.stop()
	close(r.queue)
	return err
}

func (r *simpleTunnelReader) start() {
	r.connectionInitContext, r.connectionInitContextStopFunc = context.WithCancel(context.Background())
	// go r.selfGC()
	go r.queueScheduler()
}

func (r *simpleTunnelReader) selfGC() {
	ticker := time.NewTicker(time.Hour)
	for {
		select {
		case <-r.connectionInitContext.Done():
			return
		case <-ticker.C:
			_lastUseTS := int64(atomic.LoadInt64(&r.lastUseTS))
			lastUseTS := time.Unix(_lastUseTS/1000000000, _lastUseTS%1000000000)
			if time.Since(lastUseTS) < time.Hour {
				continue
			}
			r.destroy()
			return
		}
	}
}

func (r *simpleTunnelReader) destroy() {
	r.vpn.logger.Debugf(`[simpleTunnelReader] %v destroy`, r.peerAddrRemote.ID)
	r.stop()
	err := r.Close()
	if err != nil {
		r.vpn.logger.Error(errors.Wrap(err))
	}
}

func (r *simpleTunnelReader) stop() {
	r.connectionInitContextStopFunc()
}

func (r *simpleTunnelReader) enqueue(conn *net.UDPConn, addrRemote *net.UDPAddr, msg []byte) {
	r.vpn.logger.Debugf(`[simpleTunnelReader] enqueue %v %v %v`, conn, addrRemote, msg)
	defer r.vpn.logger.Debugf(`[simpleTunnelReader] /enqueue %v %v %v`, conn, addrRemote, msg)
	atomic.StoreInt64(&r.lastUseTS, time.Now().UnixNano())
	item := acquireSimpleTunnelReaderQueueItem(uint(len(msg)))
	copy(item.msg, msg)
	item.conn = conn
	item.addrRemote = addrRemote
	r.queue <- item
}

func (r *simpleTunnelReader) queueScheduler() {
	r.vpn.logger.Debugf(`[simpleTunnelReader] queueScheduler: %v`, r.peerAddrRemote)
	defer r.vpn.logger.Debugf(`[simpleTunnelReader] /queueScheduler: %v`, r.peerAddrRemote)

	for {
		select {
		case <-r.connectionInitContext.Done():
			return
		case msg := <-r.queue:
			r.processMessage(msg)
			msg.Release()
		}
	}
}

func (r *simpleTunnelReader) processMessage(msg *simpleTunnelReaderQueueItem) {
	r.doProcessMessage(msg)

	r.vpn.logger.Debugf("[simpleTunnelReader] processMessage %v %v: %v",
		r.mySideIsReady, r.remoteSideIsReady, msg,
	)

	if r.mySideIsReady && r.remoteSideIsReady {
		conn := msg.conn
		addrRemote := msg.addrRemote
		r.vpn.logger.Debugf(`r.mySideIsReady && r.remoteSideIsReady: %v -> %v`, conn.LocalAddr(), addrRemote)

		r.connectionInitContextStopFunc()
		peer := r.vpn.GetOrCreatePeerByID(r.peerAddrRemote.ID)
		go peer.addTunnelConnection(newUDPWriter(conn, r, addrRemote), r.peerAddrRemote)
	}
}

func (r *simpleTunnelReader) doProcessMessage(msg *simpleTunnelReaderQueueItem) {
	r.vpn.logger.Debugf(`[simpleTunnelReader] doProcessMessage %v`, msg)
	defer r.vpn.logger.Debugf(`[simpleTunnelReader] /doProcessMessage %v`, msg)

	conn := msg.conn
	addrLocal := conn.LocalAddr()
	addrRemote := msg.addrRemote

	msgType := MessageType(binary.LittleEndian.Uint16(msg.msg))
	payload := msg.msg[2:]
	switch msgType {
	case MessageTypePing:
		recvTS := time.Now()
		if err := r.messagePong.MessagePing.Read(payload); err != nil {
			r.vpn.logger.Debugf("%v> incorrect ping message: %v (%v)", addrLocal, err, addrRemote)
			return
		}
		if err := r.messagePong.MessagePing.VerifySender(r.publicKeyRemote); err != nil {
			r.vpn.logger.Debugf("%v> remote signature is invalid in ping from peer %v: %v (%v)", addrLocal, r.peerAddrRemote.ID, err, addrRemote)
			return
		}

		switch r.messagePong.MessagePing.SequenceID {
		case 0:
			r.vpn.logger.Debugf("%v> remote side started to check us, let's check them too: %v", addrLocal, addrRemote)
			myPing := MessagePing{}
			myPing.SequenceID = 1
			myPing.SendTS = time.Now().UnixNano()
			if err := myPing.SignSender(r.vpn.privKey); err != nil {
				r.vpn.logger.Error(errors.Wrap(err, `unable to sign a message`, addrLocal))
				return
			}
			pingResponse := make([]byte, sizeOfMessageType+sizeOfMessagePing)
			MessageTypePing.Write(pingResponse)
			myPing.Write(pingResponse[sizeOfMessageType:])
			r.vpn.logger.Debugf(`%v> sending my-ping to %v: %v`, addrLocal, addrRemote, myPing)
			_, err := conn.WriteToUDP(pingResponse, addrRemote)
			if err != nil {
				r.vpn.logger.Debugf(`%v> unable to send a message: %v (%v)`, addrLocal, err, addrRemote)
				return
			}
		case 10:
			r.vpn.logger.Debugf("%v> remote side is ready: %v", addrLocal, addrRemote)
			r.remoteSideIsReady = true
		}

		r.messagePong.ReceiveTS = recvTS.UnixNano()
		r.messagePong.SendTS = time.Now().UnixNano()
		if err := r.messagePong.SignRecipient(r.vpn.privKey); err != nil {
			r.vpn.logger.Error(errors.Wrap(err, `unable to sign a message`, addrLocal))
			return
		}
		pongResponse := make([]byte, sizeOfMessageType+sizeOfMessagePong)
		MessageTypePong.Write(pongResponse)
		r.messagePong.Write(pongResponse[sizeOfMessageType:])
		r.vpn.logger.Debugf(`%v> sending pong to %v: %v`, addrLocal, addrRemote, r.messagePong)
		_, err := conn.WriteToUDP(pongResponse, addrRemote)
		if err != nil {
			r.vpn.logger.Debugf(`%v> unable to send a message: %v (%v)`, addrLocal, err, addrRemote)
			return
		}
		return
	case MessageTypePong:
		if err := r.messagePong.Read(payload); err != nil {
			r.vpn.logger.Error(errors.Wrap(err, "incorrect message", addrLocal, addrRemote))
			return
		}

		if err := r.messagePong.VerifyRecipient(r.publicKeyRemote); err != nil {
			r.vpn.logger.Debugf("%v> remote signature is invalid in pong from peer %v: %v (%v)", addrLocal, r.peerAddrRemote.ID, err, addrRemote)
			return
		}
		if err := r.messagePong.VerifySender(r.vpn.GetPublicKey()); err != nil {
			r.vpn.logger.Debugf("%v> my signature is invalid in pong from peer %v: %v (%v)", addrLocal, r.peerAddrRemote.ID, err, addrRemote)
			return
		}

		switch {
		case r.messagePong.SequenceID == 10:
			r.vpn.logger.Debugf("%v> my side is ready: %v", addrLocal, addrRemote)
			r.mySideIsReady = true
			return
		case r.messagePong.SequenceID <= 10:
			messagePing := &r.messagePong.MessagePing
			messagePing.SequenceID++
			messagePing.SendTS = time.Now().UnixNano()
			if err := messagePing.SignSender(r.vpn.privKey); err != nil {
				r.vpn.logger.Error(errors.Wrap(err, `unable to sign a message`, addrLocal))
				return
			}
			pingResponse := make([]byte, sizeOfMessageType+sizeOfMessagePing)
			MessageTypePing.Write(pingResponse)
			messagePing.Write(pingResponse[sizeOfMessageType:])
			r.vpn.logger.Debugf(`%v> sending ping to %v: %v`, addrLocal, addrRemote, messagePing)
			_, err := conn.WriteToUDP(pingResponse, addrRemote)
			if err != nil {
				r.vpn.logger.Debugf(`%v> unable to send a message: %v (%v)`, addrLocal, err, addrRemote)
				return
			}
			return
		default:
			r.vpn.logger.Debugf(`%v> unexpected sequence ID: %v (%v)`, addrLocal, r.messagePong.SequenceID, addrRemote)
			return
		}
	default:
		r.vpn.logger.Debugf("%v> unknown message type: %v (%v)", addrLocal, msgType, addrRemote)
		return
	}
}

func (r *simpleTunnelReader) Read(b []byte) (size int, err error) {
	size, _, err = r.ReadFromUDP(b)
	return
}

func (r *simpleTunnelReader) ReadFromUDP(b []byte) (size int, addr *net.UDPAddr, err error) {
	r.vpn.logger.Debugf(`[simpleTunnelReader] ReadFromUDP(): wait...`)
	item, ok := <-r.queue
	r.vpn.logger.Debugf(`[simpleTunnelReader] ReadFromUDP(): %v, %v`, item, ok)
	if !ok {
		return 0, nil, errors.Wrap(net.ErrClosed)
	}
	addr = item.addrRemote
	copy(b, item.msg)
	size = len(b)
	if size > len(item.msg) {
		size = len(item.msg)
	}
	item.Release()
	return
}
