package network

import (
	p2pcore "github.com/libp2p/go-libp2p-core"
	p2ppeer "github.com/libp2p/go-libp2p-core/peer"
	"time"
)

type KnownPeer struct {
	ID       p2ppeer.ID
	SitSpots []*KnownPeerSitSpot
}

type KnownPeerSitSpot struct {
	Addresses                 []p2pcore.Multiaddr
	LastSuccessfulHandshakeTS time.Time
}

type KnownPeers map[p2ppeer.ID]*KnownPeer
