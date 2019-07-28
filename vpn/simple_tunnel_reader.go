package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/crypto/ed25519"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xaionaro-go/errors"
)

const (
	simpleTunnelReaderQueueLength = 1024
)

type simpleTunnelReaderQueueItem struct {
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
	if cap(item.msg) < int(msgSize) {
		item.msg = make([]byte, msgSize)
	} else {
		item.msg = item.msg[:msgSize]
	}
	return item
}

func (item *simpleTunnelReaderQueueItem) Release() {
	simpleTunnelReaderQueueItemPool.Put(item)
}

type simpleTunnelReader struct {
	vpn                           *VPN
	peerAddrRemote                AddrInfo
	publicKeyRemote               ed25519.PublicKey
	logger                        Logger
	gcFunc                        func() error
	addrs                         []*net.UDPAddr
	lastUseTS                     uint32
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
		if cmpAddr.Port == addr.Port && bytes.Compare(cmpAddr.IP, addr.IP) == 0 {
			return true
		}
	}
	return false
}

func (r *simpleTunnelReader) Close() error {
	err := r.gcFunc()
	r.stop()
	go close(r.queue)
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
			lastUseTS := time.Unix(int64(atomic.LoadUint32(&r.lastUseTS)), 0)
			if time.Since(lastUseTS) < time.Hour {
				continue
			}
			r.destroy()
			return
		}
	}
}

func (r *simpleTunnelReader) destroy() {
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
	item := acquireSimpleTunnelReaderQueueItem(uint(len(msg)))
	copy(item.msg, msg)
	item.conn = conn
	item.addrRemote = addrRemote
	r.queue <- item
}

func (r *simpleTunnelReader) queueScheduler() {
	for {
		select {
		case <-r.connectionInitContext.Done():
			return
		case msg := <-r.queue:
			r.processMessage(msg)
		}
	}
}

func (r *simpleTunnelReader) processMessage(msg *simpleTunnelReaderQueueItem) {
	r.doProcessMessage(msg)

	if r.mySideIsReady && r.remoteSideIsReady {
		conn := msg.conn
		addrRemote := msg.addrRemote

		r.connectionInitContextStopFunc()
		peer := r.vpn.GetOrCreatePeerByID(r.peerAddrRemote.ID)
		go peer.addTunnelConnection(newUDPWriter(conn, r, addrRemote), r.peerAddrRemote)
	}

	msg.Release()
}

func (r *simpleTunnelReader) doProcessMessage(msg *simpleTunnelReaderQueueItem) {
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

		if r.messagePong.SequenceID == 11 {
			r.remoteSideIsReady = true
		}

		r.messagePong.ReceiveTS = recvTS.UnixNano()
		r.messagePong.SendTS = time.Now().UnixNano()
		if err := r.messagePong.SignRecipient(r.vpn.privKey); err != nil {
			r.vpn.logger.Error(errors.Wrap(err, `unable to sign a message`, addrLocal))
			_ = r.Close()
			return
		}
		_, err := conn.WriteToUDP(r.messagePong.Bytes(), addrRemote)
		if err != nil {
			r.vpn.logger.Debugf(`%v> unable to send a message: %v (%v)`, addrLocal, err, addrRemote)
			_ = conn.Close()
			return
		}
		return
	case MessageTypePong:
		if err := r.messagePong.Read(payload); err != nil {
			r.vpn.logger.Error(errors.Wrap(err, "incorrect message", addrLocal, addrRemote))
			return
		}

		if err := r.messagePong.VerifyRecipient(r.publicKeyRemote); err != nil {
			r.vpn.logger.Debugf("%v> remove signature is invalid in pong from peer %v: %v (%v)", addrLocal, r.peerAddrRemote.ID, err, addrRemote)
			return
		}
		if err := r.messagePong.VerifySender(r.vpn.GetPublicKey()); err != nil {
			r.vpn.logger.Debugf("%v> my signature is invalid in pong from peer %v: %v (%v)", addrLocal, r.peerAddrRemote.ID, err, addrRemote)
			return
		}

		switch {
		case r.messagePong.SequenceID <= 10:
			if r.messagePong.SequenceID == 10 {
				r.mySideIsReady = true
			}
			messagePing := &r.messagePong.MessagePing
			messagePing.SequenceID++
			if err := messagePing.SignSender(r.vpn.privKey); err != nil {
				r.vpn.logger.Error(errors.Wrap(err, `unable to sign a message`, addrLocal))
				_ = r.Close()
				return
			}
			_, err := conn.Write(messagePing.Bytes())
			if err != nil {
				r.vpn.logger.Debugf(`%v> unable to send a message: %v (%v)`, addrLocal, err, addrRemote)
				_ = conn.Close()
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
	item := <-r.queue
	addr = item.addrRemote
	copy(b, item.msg)
	size = len(b)
	if size > len(item.msg) {
		size = len(item.msg)
	}
	item.Release()
	return
}
