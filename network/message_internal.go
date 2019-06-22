package network

import (
	"sync"
)

type messageInternal struct {
	messageType
}

type messageType uint8

const (
	messageType_undefined = messageType(iota)
	messageType_updatePeer
)

var (
	messageInternalPool = sync.Pool{
		New: func() interface{} {
			return &messageInternal{}
		},
	}
)

func newMessageInternal() *messageInternal {
	return messageInternalPool.Get().(*messageInternal)
}

func (hdr *messageInternal) Reset() {
	hdr.messageType = messageType_undefined
}

func (hdr *messageInternal) Release() {
	hdr.Reset()
	messageInternalPool.Put(hdr)
}
