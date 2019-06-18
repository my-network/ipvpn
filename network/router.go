package network

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"

	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/homenet-server/iface"
)

const (
	maxPacketSize = 1500
)

var (
	ErrServiceHandlerDefined = errors.New("a service handler is defined, you cannot read data this way")
)

type Router struct {
	Network        *Network
	Peer           iface.Peer
	RealConnection io.ReadWriteCloser
	stopChan       chan struct{}
}

func NewRouter(network *Network, peer iface.Peer, realConn io.ReadWriteCloser) *Router {
	router := &Router{
		Network:        network,
		Peer:           peer,
		RealConnection: realConn,
		stopChan:       make(chan struct{}),
	}

	router.startReader()

	return router
}

func (router *Router) startReader() {
	go router.readerLoop()
}

type ReadItem struct {
	MessageHeaders MessageHeaders
	Data           []byte
}

var (
	readItemPool = sync.Pool{
		New: func() interface{} {
			item := &ReadItem{}
			item.Data = make([]byte, 0, maxPacketSize)
			return item
		},
	}
)

func NewReadItem() *ReadItem {
	return readItemPool.Get().(*ReadItem)
}

func (item *ReadItem) Reset() {
	item.MessageHeaders.Reset()
	item.Data = item.Data[:0]
}

func (item *ReadItem) Release() {
	item.Reset()
	readItemPool.Put(item)
}

func (item *ReadItem) Write(b []byte) (int, error) {
	item.Data = item.Data[:len(b)]
	copy(item.Data, b)
	return len(b), nil
}

func (router *Router) readerLoop() {
	var inputBuffer = make([]byte, maxPacketSize)
	inputBufferReader := bytes.NewReader(inputBuffer)
	logger := router.Network.logger
	for {
		select {
		case <-router.stopChan:
			close(router.stopChan)
			router.stopChan = nil
			/*for _, channels := range router.readChan {
				for _, channel := range channels {
					close(channel)
				}
			}*/
			return
		default:
		}
		logger.Debugf("n, err := router.RealConnection.Read(inputBuffer)")
		n, err := router.RealConnection.Read(inputBuffer)
		logger.Debugf("/n, err := router.RealConnection.Read(inputBuffer): %v %v", n, err)
		if err != nil {
			logger.Error(errors.Wrap(err))
			_ = router.Close()
			continue
		}
		if n == 0 {
			continue
		}

		item := NewReadItem()
		inputBufferReader.Reset(inputBuffer[:n])
		err = binary.Read(inputBufferReader, binaryBitesOrder, &item.MessageHeaders)
		if err != nil {
			logger.Error(errors.Wrap(err))
			item.Release()
			continue
		}

		logger.Debugf("[router] left bytes: %v", inputBufferReader.Len())

		_, err = inputBufferReader.WriteTo(item)
		if err != nil {
			logger.Error(errors.Wrap(err))
			item.Release()
			continue
		}

		logger.Debugf("[router] len(item.Data): %v", len(item.Data))

		if handler := router.Network.serviceHandler[item.MessageHeaders.ServiceID]; handler != nil {
			err := handler.Handle(item.MessageHeaders.AuthorID, item.Data)
			if err != nil {
				logger.Error(errors.Wrap(err), item)
				_ = router.Close()
			}
			item.Release()
			continue
		}

		/*m := router.readChan[item.MessageHeaders.ServiceID]
		ch := m[item.MessageHeaders.AuthorID]
		if ch == nil {
			ch = make(chan *ReadItem, queueLength)
			m[item.MessageHeaders.AuthorID] = ch
		}
		if len(ch) == cap(ch) {
			logger.Error("channel is overflowed, skipping a message")
			item.Release()
			continue
		}
		ch <- item*/

		logger.Infof("a message for nobody: %v", item)
		item.Release()
	}
}

func (router *Router) MessageRead(serviceID ServiceID, authorID uint32, payload []byte) error {
	if router.Network.serviceHandler[serviceID] != nil {
		return ErrServiceHandlerDefined.Wrap(serviceID, authorID, payload, len(payload))
	}

	return errors.NotImplemented.Wrap(serviceID, authorID, payload, len(payload))
}

func (router *Router) MessageWrite(serviceID ServiceID, designationID uint32, payload []byte) error {
	buf := NewBuffer()

	hdr := NewMessageHeaders()
	hdr.AuthorID = router.Network.GetPeerIntAlias()
	hdr.ServiceID = serviceID
	hdr.DesignationID = designationID
	err := binary.Write(buf, binaryBitesOrder, hdr)
	hdr.Release()
	if err != nil {
		return errors.Wrap(err, serviceID, designationID)
	}

	_, err = buf.Write(payload)
	if err != nil {
		return errors.Wrap(err, payload)
	}

	_, err = router.RealConnection.Write(buf.Bytes())
	if err != nil {
		_ = router.Close()
		return errors.Wrap(err, buf.Bytes())
	}

	buf.Release()
	return nil
}

func (router *Router) Close() error {
	go func() {
		router.stopChan <- struct{}{}
	}()
	return router.RealConnection.Close()
}

func (router *Router) IsClosed() bool {
	return router.stopChan == nil
}
