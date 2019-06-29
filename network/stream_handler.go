package network

import (
	"github.com/libp2p/go-libp2p-core/peer"
	"golang.org/x/crypto/ed25519"
)

type StreamHandler interface {
	NewStream(stream Stream, peerAddr AddrInfo)

	SetID(id peer.ID)
	SetPrivateKey(privKey ed25519.PrivateKey)
	SetPSK(psk []byte)

	Start() error
	Close() error
}
