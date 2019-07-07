package network

import (
	"testing"
	"time"

	p2pcore "github.com/libp2p/go-libp2p-core"
	p2ppeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
)

func TestKnownPeersJSON(t *testing.T) {
	peerID0Str := `12D3KooWGabcdefgh13gcGXZL8qxpAh59e9XcfCzkeKxabcdefgh`
	peerID1Str := `12D3KooWKabcdefghV7v5Ev24bW89GdRoDj22UA8DG36abcdefgh`

	var peerID0, peerID1 p2ppeer.ID

	err := peerID0.UnmarshalText([]byte(peerID0Str))
	assert.NoError(t, err)
	err = peerID1.UnmarshalText([]byte(peerID1Str))
	assert.NoError(t, err)

	knownPeers := KnownPeers{}
	knownPeers[peerID0] = &KnownPeer{
		ID: peerID0,
		SitSpots: []*KnownPeerSitSpot{
			{
				Addresses:                 []p2pcore.Multiaddr{multiaddr.Multiaddr(nil)},
				LastSuccessfulHandshakeTS: time.Date(2019, 07, 07, 17, 39, 9, 0, time.UTC),
			},
		},
	}
	knownPeers[peerID1] = &KnownPeer{
		ID: peerID1,
		SitSpots: []*KnownPeerSitSpot{
			{
				Addresses:                 []p2pcore.Multiaddr{multiaddr.Multiaddr(nil), multiaddr.Multiaddr(nil)},
				LastSuccessfulHandshakeTS: time.Date(2019, 07, 07, 17, 40, 31, 0, time.UTC),
			},
		},
	}

	knownPeersBytes, err := knownPeers.MarshalJSON()
	assert.NoError(t, err)

	deserializedKnownPeers := KnownPeers{}
	err = deserializedKnownPeers.UnmarshalJSON(knownPeersBytes)
	assert.NoError(t, err)
	assert.Equal(t, knownPeers, deserializedKnownPeers, string(knownPeersBytes))
}
