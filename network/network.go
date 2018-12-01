package network

// TODO: consider https://github.com/perlin-network/noise

import (
	"errors"
	"path/filepath"
	"sync"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/cypher"
	"github.com/xaionaro-go/homenet-peer/helpers"
)

var (
	ErrMyselfNotFound = errors.New("Not found myself in the peers list")
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
}

type network struct {
	peerID string
	peer   *models.PeerT
	peers  models.Peers
	cypher *cypher.CypherT
	locker sync.RWMutex

	hookers []Hooker
}

type Network interface {
	UpdatePeers(models.Peers) error
	GetPeerID() string
	GetPeerIntAlias() uint32
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

func New() (Network, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	cypherInstance, err := cypher.New(filepath.Join(homeDir, ".homenet"))
	if err != nil {
		return nil, err
	}

	r := &network{
		cypher: cypherInstance,
	}
	r.peerID = helpers.ToHEX(r.cypher.GetKeys().Public)

	return r, nil
}

func (homenet *network) Close() {
	homenet.RLockDo(func() {
		for _, hooker := range homenet.hookers {
			hooker.OnHomenetClose()
		}
	})
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

func (homenet *network) UpdatePeers(peers models.Peers) (err error) {
	homenet.RLockDo(func() {
		for _, peer := range peers {
			if peer.GetID() == homenet.GetPeerID() {
				homenet.peer = peer
				homenet.peers = peers
				for _, hooker := range homenet.hookers {
					if err = hooker.OnHomenetUpdatePeers(peers); err != nil {
						return
					}
				}
				return
			}
		}
		err = ErrMyselfNotFound
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
