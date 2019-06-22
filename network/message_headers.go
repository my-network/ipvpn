package network

import (
	"encoding/binary"
	"sync"
)

var (
	binaryBitesOrder = binary.LittleEndian
)

type MessageHeaders struct {
	AuthorID      uint32
	DesignationID uint32
	ServiceID     ServiceID
}

type ServiceID uint16

const (
	ServiceID_undefined = ServiceID(iota)
	ServiceID_internal
	ServiceID_vpn
	ServiceID_proxy
	ServiceID_term
	ServiceID_fs
	ServiceID_view

	ServiceIDMax
)

var (
	messageHeadersPool = sync.Pool{
		New: func() interface{} {
			return &MessageHeaders{}
		},
	}
)

func NewMessageHeaders() *MessageHeaders {
	return messageHeadersPool.Get().(*MessageHeaders)
}

func (hdr *MessageHeaders) Reset() {
	hdr.DesignationID = 0
	hdr.ServiceID = ServiceID_undefined
}

func (hdr *MessageHeaders) Release() {
	hdr.Reset()
	messageHeadersPool.Put(hdr)
}
