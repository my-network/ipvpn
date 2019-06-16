package network

// TODO: consider https://github.com/perlin-network/noise

import (
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/secureio"

	"github.com/xaionaro-go/homenet-server/iface"
	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/helpers"
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
}

type Network struct {
	connector       Connector
	peerID          string
	peer            *models.PeerT
	peers           atomic.Value
	identity        *secureio.Identity
	locker          sync.RWMutex
	peerIntAliasMap atomicmap.Map
	connectionsMap  atomicmap.Map
	logger          Logger

	hookers []Hooker
}

func (homenet *Network) RLockDo(fn func()) {
	homenet.locker.RLock()
	defer homenet.locker.RUnlock()
	fn()
}

func (homenet *Network) LockDo(fn func()) {
	homenet.locker.Lock()
	defer homenet.locker.Unlock()
	fn()
}

func New(connector Connector, logger Logger) (*Network, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	identity, err := secureio.NewIdentity(filepath.Join(homeDir, ".homenet"))
	if err != nil {
		return nil, err
	}

	r := &Network{
		connector:       connector,
		logger:          logger,
		identity:        identity,
		peerIntAliasMap: atomicmap.New(),
		connectionsMap:  atomicmap.New(),
	}
	r.peerID = helpers.ToHEX(r.identity.Keys.Public)

	return r, nil
}

func (homenet *Network) GetIdentity() *secureio.Identity {
	return homenet.identity
}

func (homenet *Network) SetConnector(connector Connector) {
	homenet.LockDo(func() {
		homenet.connector = connector
	})
}

func (homenet *Network) Close() {
	homenet.RLockDo(func() {
		for _, hooker := range homenet.hookers {
			hooker.OnHomenetClose()
		}
	})
}

func (homenet *Network) GetPeerByIntAlias(peerIntAlias uint32) *models.PeerT {
	r, _ := homenet.peerIntAliasMap.Get(peerIntAlias)
	if r == nil {
		return nil
	}
	return r.(*models.PeerT)
}

func (homenet *Network) AddHooker(newHooker Hooker) {
	homenet.LockDo(func() {
		homenet.hookers = append(homenet.hookers, newHooker)
	})
}

func (homenet *Network) RemoveHooker(removeHooker Hooker) {
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

func (homenet *Network) GetPeers() models.Peers {
	peers := homenet.peers.Load()
	if peers == nil {
		return nil
	}
	return peers.(models.Peers)
}

func (homenet *Network) GetConnectionTo(peer iface.Peer) net.Conn {
	conn, _ := homenet.connectionsMap.Get(peer.GetID())
	if conn == nil {
		return nil
	}
	return conn.(net.Conn)
}

type sessionErrorHandler struct {
	homenet *Network
	peer    iface.Peer
}

func (errHandler *sessionErrorHandler) Error(sess *secureio.Session, err error) {
	errHandler.homenet.logger.Error(err)
	_ = errHandler.homenet.connectionsMap.Unset(errHandler.peer.GetID())
	_ = sess.Close()
}

func (errHandler *sessionErrorHandler) Infof(fm string, args ...interface{}) {
	errHandler.homenet.logger.Infof(fm, args)
}

func (errHandler *sessionErrorHandler) Debugf(fm string, args ...interface{}) {
	errHandler.homenet.logger.Debugf(fm, args)
}

func (homenet *Network) EstablishConnectionTo(peer iface.Peer) io.ReadWriteCloser {
	if conn := homenet.GetConnectionTo(peer); conn != nil {
		// We don't need to do anything if we already have a working connection
		return conn
	}

	realConn, err := homenet.connector.NewConnection(homenet.peer, peer)
	if realConn == nil || err != nil {
		homenet.logger.Error("I was unable to connect to ", peer.GetID(), ": err == ", err)
		return nil
	}
	conn := homenet.identity.NewSession(secureio.NewRemoteIdentityFromPublicKey(peer.GetPublicKey()), realConn, &sessionErrorHandler{
		homenet,
		peer,
	})

	oldConn, err := homenet.connectionsMap.Swap(peer.GetID(), conn)
	if oldConn != nil {
		// If somebody already putted a connection for this peer (while another goroutine), then we need to close it :(
		// It was somekind of a race condition. And here we are cleaning things up.
		_ = oldConn.(io.Closer).Close()
	}
	if err != nil {

	}

	return conn
}

func (homenet *Network) logError(err error) {
	if err == nil {
		return
	}
	homenet.logger.Error("[homenet-network] got error: ", err)
}

func (homenet *Network) UpdatePeers(peers models.Peers) (err error) {
	homenet.RLockDo(func() {
		oldPeers := homenet.GetPeers()
		removePeerIDs := atomicmap.NewWithArgs(uint64(len(oldPeers))*3/2 + 1) // it's just faster than Go's bultin maps
		for _, peer := range oldPeers {
			homenet.logError(removePeerIDs.Set(peer.GetID(), struct{}{}))
		}
		foundMyself := false
		for _, peer := range peers {
			peerID := peer.GetID()
			_ = removePeerIDs.Unset(peerID)
			if peerID == homenet.GetPeerID() {
				homenet.peer = peer
				foundMyself = true
			}
			homenet.logError(homenet.peerIntAliasMap.Set(peerID, peer))
		}
		if !foundMyself {
			err = errors.Wrap(ErrMyselfNotFound)
			return
		}
		for removePeerID := range removePeerIDs.Keys() {
			homenet.logError(homenet.peerIntAliasMap.Unset(removePeerID))
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

func (homenet *Network) GetPeerIntAlias() (r uint32) {
	homenet.RLockDo(func() {
		r = homenet.peer.GetIntAlias()
	})
	return
}

func (homenet *Network) GetPeerID() string {
	return homenet.peerID
}
