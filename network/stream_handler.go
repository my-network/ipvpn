package network

import (
	"github.com/libp2p/go-libp2p-core/peer"
)

type StreamHandler interface {
	SetID(id peer.ID)
	NewStream(stream Stream)
}
