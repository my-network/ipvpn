package network

import (
	"path/filepath"
	"sync"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/cypher"
	"github.com/xaionaro-go/homenet-peer/helpers"
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
}

type network struct {
	peerID    string
	cypher    *cypher.CypherT
	locker    sync.Mutex

	hookers []Hooker
}

type Network interface {
	UpdatePeers(models.Peers) error
	GetPeerID() string
	AddHooker(newHooker Hooker)
	RemoveHooker(removeHooker Hooker)
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

func (homenet *network) UpdatePeers(peers models.Peers) error {
	return nil
}

func (homenet *network) GetPeerID() string {
	return homenet.peerID
}
