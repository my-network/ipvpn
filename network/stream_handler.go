package network

import (
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/ed25519"
)

type StreamHandler interface {
	SetNetwork(network *Network)

	ProtocolID() protocol.ID

	NewStream(stream Stream, peerAddr AddrInfo)
	ConsiderKnownPeer(peerAddr AddrInfo)

	SetID(id peer.ID)
	SetPrivateKey(privKey ed25519.PrivateKey)
	SetPSK(psk []byte)
	SetMyAddrs(addrs []multiaddr.Multiaddr)

	IsBadAddress(maddr multiaddr.Multiaddr) bool

	Start() error
	Close() error
}
