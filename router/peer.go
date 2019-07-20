package router

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/my-network/ipvpn/helpers"
	"github.com/my-network/ipvpn/vpn"
)

type Peer struct {
	locker       sync.RWMutex
	id           PeerID
	ip           net.IP
	router       *Router
	directRoutes [vpn.ChannelType_max]*DirectRoute

	streamOutgoing Stream
	streamIngoing  Stream
}

func newPeer(router *Router, peerID PeerID) *Peer {
	peer := &Peer{
		id:     peerID,
		router: router,
	}

	go peer.startOutgoingConnection()

	return peer
}

func (peer *Peer) LockDo(fn func()) {
	peer.locker.Lock()
	defer peer.locker.Unlock()
	fn()
}

func (peer *Peer) RLockDo(fn func()) {
	peer.locker.RLock()
	defer peer.locker.RUnlock()
	fn()
}

func (peer *Peer) Stream() (result Stream) {
	peer.RLockDo(func() {
		if peer.streamIngoing != nil {
			result = peer.streamIngoing
			return
		}
		result = peer.streamOutgoing
	})
	return
}

func (peer *Peer) ID() PeerID {
	return peer.id
}

func (peer *Peer) startOutgoingConnection() {
	peer.LockDo(func() {
		if peer.streamOutgoing != nil {
			panic(`peer.streamOutgoing != nil`)
		}
		streamOutgoing := helpers.NewReconnectableStream(peer.router.logger, func() (Stream, error) {
			return peer.router.mesh.NewStream(peer.id, peer.router.ProtocolID())
		})
		go streamOutgoing.Connect()
		peer.streamOutgoing = streamOutgoing
	})
}

func (peer *Peer) IP() (result net.IP) {
	peer.RLockDo(func() {
		result = peer.ip
	})
	return
}

func (peer *Peer) SetIP(newIP net.IP) {
	peer.LockDo(func() {
		peer.ip = newIP
	})
}

func (peer *Peer) SetDirectRoute(chType ChannelType, ip net.IP) {
	peer.LockDo(func() {
		directRoute := peer.directRoutes[chType]
		if directRoute == nil {
			directRoute = newDirectRoute(peer, chType, ip)
			peer.directRoutes[chType] = directRoute
		} else {
			directRoute.SetDestination(ip)
		}
	})
}

func (peer *Peer) MeasureLatencies(ctx context.Context) context.Context {
	var cancelFunc context.CancelFunc
	if ctx == nil {
		ctx, cancelFunc = context.WithTimeout(context.Background(), time.Second*5)
	}

	var wg sync.WaitGroup
	for _, route := range peer.DirectRoutes() {
		wg.Add(1)
		go func() {
			route.MeasureLatency(ctx)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		if cancelFunc != nil {
			cancelFunc()
		}
	}()
	return ctx
}

func (peer *Peer) DirectRoutes() (result []*DirectRoute) {
	peer.RLockDo(func() {
		for _, route := range peer.directRoutes {
			if route == nil {
				continue
			}
			result = append(result, route)
		}
	})
	return
}
