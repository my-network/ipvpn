package network

// TODO: consider https://github.com/perlin-network/noise

import (
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"


	"github.com/xaionaro-go/homenet-server/iface"
	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/cypher"
	"github.com/xaionaro-go/homenet-peer/helpers"
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
}

type network struct {
	connector      Connector
	peerID          string
	peer            *models.PeerT
	peers           atomic.Value
	cypher          *cypher.CypherT
	locker          sync.RWMutex
	peerIntAliasMap atomicmap.Map
	connectionsMap  atomicmap.Map

	hookers []Hooker
}

type Network interface {
	SetConnector(connector Connector)
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
		cypher:          cypherInstance,
		peerIntAliasMap: atomicmap.New(),
		connectionsMap:  atomicmap.New(),
	}
	r.peerID = helpers.ToHEX(r.cypher.GetKeys().Public)

	return r, nil
}

func (homenet *network) SetConnector(connector Connector) {
	homenet.LockDo(func() {
		homenet.connector = connector
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

func (homenet *network) GetConnectionTo(peer iface.Peer) net.Conn {
	conn, _ := homenet.connectionsMap.Get(peer.GetID())
	if conn == nil {
		return nil
	}
	return conn.(net.Conn)
}

func (homenet *network) EstablishConnectionTo(peer iface.Peer) net.Conn {
	if conn := homenet.GetConnectionTo(peer); conn != nil {
		// We don't need to do anything if we already have a working connection
		return conn
	}

	conn, err := homenet.connector.NewConnection(homenet.peer, peer, homenet.cypher.NewSession(peer.GetID()))
	if conn == nil || err != nil {
		homenet.loggerError.Printf("I was unable to connect to %v: err = %v", peer.GetID(), err)
		return nil
	}

	oldConn := homenet.connections.Swap(peer.GetID(), conn)
	if oldConn != nil {
		// If somebody already putted a connection for this peer in an other goroutined, then we need to close it :(
		// It was somekind of a race condition. And here we are cleaning things up.
		oldConn.Close()
	}

	return conn
}

func (homenet *network) UpdatePeers(peers models.Peers) (err error) {
	homenet.RLockDo(func() {
		oldPeers := homenet.GetPeers()
		removePeerIDs := atomicmap.NewWithArgs(uint64(len(oldPeers))*3/2 + 1) // it's just faster than Go's bultin maps
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
		if !foundMyself {
			err = errors.Wrap(ErrMyselfNotFound)
			return
		}
		for removePeerID, _ := range removePeerIDs.Keys() {
			homenet.peerIntAliasMap.Unset(removePeerID)
		}
		homenet.peers.Store(peers)
		for _, peer := range peers {
			go homenet.EstablishConnectionTo(peer)
		}
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
