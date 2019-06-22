package network

// TODO: consider https://github.com/perlin-network/noise

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mitchellh/go-homedir"

	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/secureio"

	"github.com/xaionaro-go/homenet-server/iface"
	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/helpers"
)

const (
	connectionRetryInitialDelay = time.Second
	refusedTryLimit             = 30
	signatureTryLimit           = 3
)

type Hooker interface {
	OnHomenetClose()
	OnHomenetUpdatePeers(models.Peers) error
	OnHomenetConnectPeer(peer iface.Peer) error
}

type Handler interface {
	Handle(authorID uint32, payload []byte) error
}

type Network struct {
	connector            Connector
	peerID               string
	peer                 *models.PeerT
	peers                atomic.Value
	identity             *secureio.Identity
	peerIDMap            atomicmap.Map
	peerIntAliasMap      atomicmap.Map
	directConnectionsMap atomicmap.Map
	routersMap           atomicmap.Map
	pathMap              atomicmap.Map
	logger               Logger
	serviceHandler       map[ServiceID]Handler
	updatePeersLocker    sync.RWMutex

	hookers []Hooker
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
		connector:            connector,
		logger:               logger,
		identity:             identity,
		directConnectionsMap: atomicmap.New(),
		routersMap:           atomicmap.New(),
		pathMap:              atomicmap.New(),
		peerIDMap:            atomicmap.New(),
		peerIntAliasMap:      atomicmap.New(),
		serviceHandler:       make(map[ServiceID]Handler),
	}
	r.peers.Store(models.Peers{})
	r.peerID = helpers.ToHEX(r.identity.Keys.Public)

	return r, nil
}

func (homenet *Network) GetIdentity() *secureio.Identity {
	return homenet.identity
}

func (homenet *Network) SetConnector(connector Connector) {
	homenet.connector = connector
}

func (homenet *Network) Close() {
	for _, hooker := range homenet.hookers {
		hooker.OnHomenetClose()
	}
}

func (homenet *Network) GetPeerByIntAlias(peerIntAlias uint32) *models.PeerT {
	r, _ := homenet.peerIntAliasMap.Get(peerIntAlias)
	if r == nil {
		return nil
	}
	return r.(*models.PeerT)
}

func (homenet *Network) SetServiceHandler(serviceID ServiceID, handler Handler) {
	homenet.serviceHandler[serviceID] = handler
}

func (homenet *Network) AddHooker(newHooker Hooker) {
	homenet.hookers = append(homenet.hookers, newHooker)
}

func (homenet *Network) RemoveHooker(removeHooker Hooker) {
	var leftHookers []Hooker
	for _, hooker := range homenet.hookers {
		if hooker == removeHooker {
			continue
		}
		leftHookers = append(leftHookers, hooker)
	}
	homenet.hookers = leftHookers
}

func (homenet *Network) GetPeers() models.Peers {
	peers := homenet.peers.Load()
	if peers == nil {
		return nil
	}
	return peers.(models.Peers)
}

func (homenet *Network) GetPathTo(peer iface.Peer) *Path {
	path, _ := homenet.pathMap.Get(peer.GetID())
	if path == nil {
		return nil
	}
	return path.(*Path)
}

func (homenet *Network) GetPipeTo(peer iface.Peer, serviceID ServiceID) io.ReadWriter {
	path := homenet.GetPathTo(peer)
	if path == nil {
		return nil
	}
	return path.GetReadWriter(serviceID)
}

func (homenet *Network) GetDirectConnectionTo(peer iface.Peer) io.ReadWriteCloser {
	conn, _ := homenet.directConnectionsMap.Get(peer.GetID())
	if conn == nil {
		return nil
	}
	return conn.(io.ReadWriteCloser)
}

type sessionErrorHandler struct {
	isClosed           uint32
	homenet            *Network
	peer               *models.PeerT
	refusedTryNumber   uint
	tryNumber          uint
	signatureTryNumber uint
}

func (errHandler *sessionErrorHandler) OnConnect(sess *secureio.Session) {
	errHandler.peer.SetLastSuccessfulNegotiationPair(errHandler.peer.GetLastNegotiationPair())

	for _, hooker := range errHandler.homenet.hookers {
		if err := hooker.OnHomenetConnectPeer(errHandler.peer); err != nil {
			return
		}
	}
}

func (errHandler *sessionErrorHandler) considerFail(sess *secureio.Session) {
	atomic.StoreUint32(&errHandler.isClosed, 1)
	errHandler.homenet.logger.Debugf("sessionErrorHandler: considerFail")
	_ = errHandler.homenet.directConnectionsMap.Unset(errHandler.peer.GetID())
	_ = errHandler.homenet.routersMap.Unset(errHandler.peer.GetID())
	_ = errHandler.homenet.pathMap.Unset(errHandler.peer.GetID())
	_ = sess.Close()

	go func() {
		delayBeforeRetry := connectionRetryInitialDelay //* time.Duration(1<<errHandler.tryNumber)
		errHandler.homenet.logger.Debugf("retry (try: %v) in %v...", errHandler.tryNumber, delayBeforeRetry)
		time.Sleep(delayBeforeRetry)
		errHandler.homenet.establishConnectionTo(errHandler.peer, errHandler.tryNumber+1)
	}()
}

func (errHandler *sessionErrorHandler) IsClosed() bool {
	return atomic.LoadUint32(&errHandler.isClosed) != 0
}

func (errHandler *sessionErrorHandler) Error(sess *secureio.Session, err error) {
	if errHandler.IsClosed() {
		return
	}
	err = err.(errors.SmartError).OriginalError()
	errHandler.homenet.logger.Debugf("sessionErrorHandler: %T:%v", err, err)
	if netErr, ok := err.(*net.OpError); ok {
		errHandler.homenet.logger.Debugf("sessionErrorHandler: net error: %T:%v", netErr.Err, netErr.Err)
		if osErr, ok := netErr.Err.(*os.SyscallError); ok {
			errHandler.homenet.logger.Debugf("sessionErrorHandler: net os error: %T:%v", osErr.Err, osErr.Err)
			if osErr.Err == syscall.ECONNREFUSED {
				errHandler.refusedTryNumber++
				if errHandler.refusedTryNumber < refusedTryLimit {
					errHandler.homenet.logger.Debugf("connection refused by remote side, retry.")
					return
				}
				errHandler.homenet.logger.Infof("connection refused by remote side")
				errHandler.considerFail(sess)
				return
			}
		}
	}
	if err == secureio.ErrInvalidSignature {
		errHandler.signatureTryNumber++
		if errHandler.signatureTryNumber < signatureTryLimit {
			errHandler.homenet.logger.Infof("invalid signature, retry.")
			return
		}
		errHandler.homenet.logger.Infof("invalid signature.")
		errHandler.considerFail(sess)
		return
	}

	errHandler.homenet.logger.Error(err)
	errHandler.considerFail(sess)
}

func (errHandler *sessionErrorHandler) Infof(fm string, args ...interface{}) {
	errHandler.homenet.logger.Infof(fm, args...)
}

func (errHandler *sessionErrorHandler) Debugf(fm string, args ...interface{}) {
	errHandler.homenet.logger.Debugf(fm, args...)
}

func (homenet *Network) establishConnectionTo(peer iface.Peer, tryNumber uint) {
	if conn := homenet.GetDirectConnectionTo(peer); conn != nil {
		// We don't need to do anything if we already have a working connection
		return
	}

	homenet.logger.Debugf("establishing a connection to %v %v", peer.GetIntAlias(), peer.GetID())
	realConn, err := homenet.connector.NewConnection(homenet.peer, peer.(*models.PeerT))
	if realConn == nil || err != nil {
		homenet.logger.Infof("we were unable to connect to %v: realConn is nil: %v;  err == %v", peer.GetID(), realConn == nil, err)
		go func() {
			time.Sleep(connectionRetryInitialDelay * time.Duration(1<<tryNumber))
			homenet.establishConnectionTo(peer, tryNumber+1)
		}()
		return
	}

	homenet.logger.Debugf("securing the connection to %v %v", peer.GetIntAlias(), peer.GetID())
	if len(peer.GetPublicKey()) == 0 {
		homenet.logger.Error("peer's public key is empty")
		return
	}
	conn := homenet.identity.NewSession(secureio.NewRemoteIdentityFromPublicKey(peer.GetPublicKey()), realConn, &sessionErrorHandler{
		homenet:   homenet,
		peer:      peer.(*models.PeerT),
		tryNumber: tryNumber,
	})

	homenet.logger.Debugf("saving the connection to %v %v", peer.GetIntAlias(), peer.GetID())
	homenet.saveDirectConnection(peer, conn)

	return
}

func (homenet *Network) logError(err error) {
	if err == nil {
		return
	}
	homenet.logger.Error("[homenet-network] got error: ", err)
}

func (homenet *Network) saveDirectConnection(peer iface.Peer, conn io.ReadWriteCloser) {
	oldConn, err := homenet.directConnectionsMap.Swap(peer.GetID(), conn)
	if oldConn != nil {
		// If somebody already putted a connection for this peer (while another goroutine), then we need to close it :(
		// It was somekind of a race condition. And here we are cleaning things up.
		homenet.logger.Debugf("closing the previous connection to %v %v", peer.GetIntAlias(), peer.GetID())
		_ = oldConn.(io.Closer).Close()
	}
	if err != nil {
		homenet.logError(errors.Wrap(err))
	}

	homenet.setupRouter(peer, conn)
	homenet.updatePaths()
}

func (homenet *Network) setupRouter(peer iface.Peer, conn io.ReadWriteCloser) {
	router := NewRouter(homenet, peer, conn)
	oldRouter, _ := homenet.routersMap.Swap(peer.GetID(), router)
	if oldRouter != nil {
		_ = oldRouter.(*Router).Close()
	}
}

func (homenet *Network) updatePaths() {
	for _, peer := range homenet.GetPeers() {
		pathI, _ := homenet.pathMap.Get(peer.GetID())
		if pathI != nil {
			path := pathI.(*Path)
			if path.IsValid() {
				continue
			}
		}

		var router *Router
		routerI, _ := homenet.routersMap.Get(peer.GetID())
		if routerI == nil {
			continue
		}
		router = routerI.(*Router)
		oldPath, _ := homenet.pathMap.Swap(peer.GetID(), NewPath(peer, router))
		if oldPath != nil {
			_ = oldPath.(*Path).Close()
		}
	}
}

func ParsePeersFromFile(filePath string) (result models.Peers, err error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	err = json.Unmarshal(b, &result)
	return
}

func SavePeersToFile(filePath string, peers models.Peers) error {
	b, err := json.Marshal(peers)
	if err != nil {
		return errors.Wrap(err)
	}
	return ioutil.WriteFile(filePath, b, 0640)
}

func (homenet *Network) onNewPeer(peer *models.PeerT) {
	homenet.logger.Debugf("new peer: %v %v (is_me: %v)", peer.GetIntAlias(), peer.GetID(), peer.GetID() == homenet.GetPeerID())
	if peer.GetID() == homenet.GetPeerID() {
		homenet.peer = peer
		return
	}
	go homenet.establishConnectionTo(peer, 0)
}

func (homenet *Network) UpdatePeers(peers models.Peers) (err error) {
	homenet.updatePeersLocker.Lock()
	defer homenet.updatePeersLocker.Unlock()

	dontRemoveMap := map[string]bool{}
	var oldPeers models.Peers
	var newPeers models.Peers
	for _, peer := range peers {
		oldPeerI, _ := homenet.peerIDMap.Get(peer.GetID())
		if oldPeerI == nil {
			newPeers = append(newPeers, peer)
		} else {
			oldPeer := oldPeerI.(*models.PeerT)
			oldPeers = append(oldPeers, oldPeer)
			dontRemoveMap[peer.GetID()] = true

			if peer.GetIntAlias() != oldPeer.GetIntAlias() {
				_ = homenet.peerIntAliasMap.Unset(oldPeer.GetIntAlias())
				oldPeer.SetIntAlias(peer.GetIntAlias())
				_ = homenet.peerIntAliasMap.Set(oldPeer.GetIntAlias(), oldPeer)
			}
		}
	}

	for _, peer := range homenet.peers.Load().(models.Peers) {
		peerID := peer.GetID()
		if dontRemoveMap[peerID] {
			continue
		}
		_ = homenet.peerIDMap.Unset(peerID)
		_ = homenet.peerIntAliasMap.Unset(peer.GetIntAlias())
	}

	for _, peer := range newPeers {
		_ = homenet.peerIDMap.Set(peer.GetID(), peer)
		_ = homenet.peerIntAliasMap.Set(peer.GetIntAlias(), peer)
	}

	homenet.peers.Store(append(oldPeers, newPeers...))

	for _, peer := range newPeers {
		homenet.onNewPeer(peer)
	}

	for _, hooker := range homenet.hookers {
		if err = hooker.OnHomenetUpdatePeers(peers); err != nil {
			return
		}
	}
	return
}

func (homenet *Network) GetPeerIntAlias() (r uint32) {
	return homenet.peer.GetIntAlias()
}

func (homenet *Network) GetPeerID() string {
	return homenet.peerID
}
