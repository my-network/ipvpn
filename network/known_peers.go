package network

import (
	"encoding/json"
	p2ppeer "github.com/libp2p/go-libp2p-core/peer"
	"time"
)

type KnownPeer struct {
	ID       p2ppeer.ID
	SitSpots []*KnownPeerSitSpot
}

type KnownPeerSitSpot struct {
	Addresses                 []string
	LastSuccessfulHandshakeTS time.Time
}

type KnownPeers map[p2ppeer.ID]*KnownPeer

func (peers KnownPeers) MarshalJSON() ([]byte, error) {
	slice := make([]*KnownPeer, 0, len(peers))
	for _, peer := range peers {
		slice = append(slice, peer)
	}
	return json.Marshal(slice)
}

func (peers KnownPeers) Reset() error {
	for k := range peers {
		delete(peers, k)
	}

	return nil
}

func (peers *KnownPeers) UnmarshalJSON(b []byte) error {
	var slice []*KnownPeer
	if err := json.Unmarshal(b, &slice); err != nil {
		return err
	}

	_ = peers.Reset()

	for _, peer := range slice {
		(*peers)[peer.ID] = peer
	}

	return nil
}
