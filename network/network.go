package network

// TODO: consider https://github.com/perlin-network/noise

import (
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/cypher"
	"github.com/xaionaro-go/homenet-peer/helpers"
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
}

type network struct {
	negotiator      Negotiator
	peerID          string
	peer            *models.PeerT
	peers           atomic.Value
	cypher          *cypher.CypherT
	locker          sync.RWMutex
	peerIntAliasMap atomicmap.Map

	hookers []Hooker
}

type Network interface {
	SetNegotiator(negotiator Negotiator)
	GetPeers() models.Peers
	UpdatePeers(models.Peers) error
	GetPeerID() string
	GetPeerIntAlias() uint32
	GetPeerByIntAlias(peerIntAlias uint32) *models.PeerT
	AddHooker(newHooker Hooker)
	RemoveHooker(removeHooker Hooker)
	Close()
}

func (homenet *network) RLockDo(fn func()) {
	homenet.locker.RLock()
	defer homenet.locker.RUnlock()
	fn()
}

func (homenet *network) LockDo(fn func()) {
	homenet.locker.Lock()
	defer homenet.locker.Unlock()
	fn()
}

func New(negotiator Negotiator) (Network, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	cypherInstance, err := cypher.New(filepath.Join(homeDir, ".homenet"))
	if err != nil {
		return nil, err
	}

	r := &network{
		cypher:          cypherInstance,
		peerIntAliasMap: atomicmap.New(),
		negotiator:      negotiator,
	}
	r.peerID = helpers.ToHEX(r.cypher.GetKeys().Public)

	return r, nil
}

func (homenet *network) SetNegotiator(negotiator Negotiator) {
	homenet.LockDo(func() {
		homenet.negotiator = negotiator
	})
}

func (homenet *network) Close() {
	homenet.RLockDo(func() {
		for _, hooker := range homenet.hookers {
			hooker.OnHomenetClose()
		}
	})
}

func (homenet *network) GetPeerByIntAlias(peerIntAlias uint32) *models.PeerT {
	r, _ := homenet.peerIntAliasMap.Get(peerIntAlias)
	if r == nil {
		return nil
	}
	return r.(*models.PeerT)
}

func (homenet *network) AddHooker(newHooker Hooker) {
	homenet.LockDo(func() {
		homenet.hookers = append(homenet.hookers, newHooker)
	})
}

func (homenet *network) RemoveHooker(removeHooker Hooker) {
	homenet.LockDo(func() {
		var leftHookers []Hooker
		for _, hooker := range homenet.hookers {
			if hooker == removeHooker {
				continue
			}
			leftHookers = append(leftHookers, hooker)
		}
		homenet.hookers = leftHookers
	})
}

func (homenet *network) GetPeers() models.Peers {
	peers := homenet.peers.Load()
	if peers == nil {
		return nil
	}
	return peers.(models.Peers)
}

func (homenet *network) UpdatePeers(peers models.Peers) (err error) {
	homenet.RLockDo(func() {
		oldPeers := homenet.GetPeers()
		removePeerIDs := atomicmap.NewWithArgs(uint64(len(oldPeers))*3/2+1, nil) // it's just faster than Go's bultin maps
		for _, peer := range oldPeers {
			removePeerIDs.Set(peer.GetID(), struct{}{})
		}
		foundMyself := false
		for _, peer := range peers {
			peerID := peer.GetID()
			removePeerIDs.Unset(peerID)
			if peerID == homenet.GetPeerID() {
				homenet.peer = peer
				foundMyself = true
			}
			homenet.peerIntAliasMap.Set(peerID, peer)
		}
		for removePeerID, _ := range removePeerIDs.Keys() {
			homenet.peerIntAliasMap.Unset(removePeerID)
		}
		if !foundMyself {
			err = errors.Wrap(ErrMyselfNotFound)
			return
		}
		homenet.peers.Store(peers)
		for _, hooker := range homenet.hookers {
			if err = hooker.OnHomenetUpdatePeers(peers); err != nil {
				return
			}
		}
	})
	return
}

func (homenet *network) GetPeerIntAlias() (r uint32) {
	homenet.RLockDo(func() {
		r = homenet.peer.GetIntAlias()
	})
	return
}

func (homenet *network) GetPeerID() string {
	return homenet.peerID
}
