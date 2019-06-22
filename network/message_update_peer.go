package network

import (
	"sync"

	"github.com/xaionaro-go/homenet-server/models"
)

type messageUpdatePeer struct {
	State state
	Peer  models.PeerT
}

type state uint8

const (
	state_undefined = state(iota)
	state_update
	state_remove
)

var (
	messageUpdatePeerPool = sync.Pool{
		New: func() interface{} {
			return &MessageHeaders{}
		},
	}
)

func newMessageUpdatePeer() *messageUpdatePeer {
	return messageUpdatePeerPool.Get().(*messageUpdatePeer)
}

func (hdr *messageUpdatePeer) Reset() {
	hdr.State = state_undefined
	hdr.Peer = models.PeerT{}
}

func (hdr *messageUpdatePeer) Release() {
	hdr.Reset()
	messageHeadersPool.Put(hdr)
}
