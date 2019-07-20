package router

import (
	"context"
	"github.com/my-network/ipvpn/eventbus"
	"golang.org/x/crypto/ed25519"
	"math"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/ipvpn/vpn"
	"github.com/my-network/routewrapper"
	"github.com/xaionaro-go/atomicmap"
	"github.com/xaionaro-go/errors"
)

const (
	routerProtocolID = protocol.ID(`/p2p/github.com/my-network/ipvpn/router`)
)

type Router struct {
	eventBus eventbus.EventBus
	context   context.Context
	stopFunc  context.CancelFunc
	locker    sync.RWMutex
	routeMgmt routewrapper.Routing
	mesh      *network.Network
	logger    Logger
	peers     atomicmap.Map
}

func New(eventBus eventbus.EventBus, logger Logger) *Router {
	routeMgmt, err := routewrapper.NewRouteWrapper()
	if err != nil {
		panic(err)
	}

	router := &Router{
		eventBus:eventBus,
		routeMgmt: routeMgmt,
		logger:    logger,
		peers:     atomicmap.New(),
	}
	router.context, router.stopFunc = context.WithCancel(context.Background())

	router.start()

	return router
}

func (router *Router) start() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		for {
			select {
			case <-router.context.Done():
				return
			case <-ticker.C:
			}

			router.updateRoutes()
		}
	}()
}

func (router *Router) ProtocolID() protocol.ID {
	return routerProtocolID
}

func (router *Router) SetNetwork(mesh *network.Network) {
	router.mesh = mesh
}

func (router *Router) OnUpdateMyIP(ip net.IP) {

}

func (router *Router) OnPeerConnect(peerID PeerID, chType vpn.ChannelType, ip net.IP) {
	router.logger.Debugf(`OnPeerConnect(%v, %v, %v)`, peerID, chType, ip)

	router.considerNewRoute(router.createPeerIfNotExists(peerID), chType, ip)
}

func (router *Router) GetPeer(peerID PeerID) *Peer {
	peerI, _ := router.peers.Get(peerID)
	if peerI == nil {
		return nil
	}
	return peerI.(*Peer)
}

func (router *Router) createPeerIfNotExists(peerID PeerID) (peer *Peer) {
	peer = router.GetPeer(peerID)
	if peer != nil {
		return
	}
	router.locker.Lock()
	if peer = router.GetPeer(peerID); peer == nil {
		peer = newPeer(router, peerID)
		_ = router.peers.Set(peerID, peer)
	}
	router.locker.Unlock()
	return
}

func (router *Router) updateRoutes() {
	for _, peerID := range router.peers.Keys() {
		peer, _ := router.peers.Get(peerID)
		if peer == nil {
			continue
		}

		router.updatePeerRoutes(peer.(*Peer))
	}
}

func (router *Router) updatePeerRoutes(peer *Peer) {
	router.logger.Debugf(`considerNewRoute: measuring latencies`)
	ctx := peer.MeasureLatencies(nil)

	osRoutes, err := router.routeMgmt.Routes()
	if err != nil {
		router.logger.Error(errors.Wrap(err, `unable to get current routes`))
		return
	}

	oldRoutes := map[string]*routewrapper.Route{}
	for idx := range osRoutes {
		osRoute := &osRoutes[idx]
		oldRoutes[osRoute.Gateway.String()] = osRoute
	}

	ipnet := net.IPNet{
		IP: peer.IP(),
	}
	if peer.IP().To4() == nil {
		ipnet.Mask = net.CIDRMask(32, 32)
	} else {
		ipnet.Mask = net.CIDRMask(128, 128)
	}

	select {
	case <-ctx.Done():
	}

	for _, route := range peer.DirectRoutes() {
		ip := route.Destination()
		metric := int(1000 + math.Log2(float64(route.Latency().Nanoseconds()))*100)
		switch route.channelType {
		case ChannelTypeDirect:
		case ChannelTypeTunnel:
			metric += 50
		case ChannelTypeIPFS:
			metric += 100
		}
		metric += int(float64(300) * route.TimedOutFraction())
		oldRoute := oldRoutes[ip.String()]
		if oldRoute != nil {
			if oldRoute.Metric == metric {
				continue
			}
			router.logger.Debugf(`considerNewRoute: removing an old route %v`, oldRoute)
			err := router.routeMgmt.RemoveRoute(*oldRoute)
			if err != nil {
				router.logger.Error(errors.Wrap(err, `unable to remove an old route`, oldRoute))
			}
		}

		newRoute := routewrapper.Route{
			Destination: ipnet,
			Gateway:     ip,
			Metric:      metric,
		}
		router.logger.Debugf(`considerNewRoute: adding a new route %v`, newRoute)
		err := router.routeMgmt.AddRoute(newRoute)
		if err != nil {
			router.logger.Error(errors.Wrap(err, `unable to add a new route`, newRoute))
		}
	}
}

func (router *Router) considerNewRoute(peer *Peer, chType vpn.ChannelType, ip net.IP) {
	if chType == ChannelTypeAutoRouted {
		peer.SetIP(ip)
		return
	}

	peer.SetDirectRoute(chType, ip)

	for _, delay := range []time.Duration{
		time.Second,
		5 * time.Second,
		30 * time.Second,
		time.Minute,
		5 * time.Minute,
	} {
		router.logger.Debugf(`considerNewRoute: sleep for %v`, delay)
		time.Sleep(delay)

		router.updatePeerRoutes(peer)
	}
}

func (router *Router) NewStream(stream Stream, peerAddr AddrInfo) {
	router.logger.Debugf(`new stream from %v`, peerAddr.ID)
	peer := router.createPeerIfNotExists(peerAddr.ID)

	peer.LockDo(func() {
		streamIngoingOld := peer.streamIngoing
		peer.streamIngoing = stream
		if streamIngoingOld != nil {
			router.logger.Debugf(`closing old ingoing stream from %v`, peer.ID())
			_ = streamIngoingOld.Close()
		}
	})
}

func (router *Router) OnPeerDisconnect(peerID PeerID, chType vpn.ChannelType) {

}

func (router *Router) ConsiderKnownPeer(peerAddr AddrInfo) {

}

func (router *Router) SetID(id PeerID) {

}
func (router *Router) SetPrivateKey(privKey ed25519.PrivateKey) {

}
func (router *Router) SetPSK(psk []byte) {

}
func (router *Router) SetMyAddrs(addrs []multiaddr.Multiaddr) {

}

func (router *Router) IsBadAddress(maddr multiaddr.Multiaddr) bool {
	return false
}

func (router *Router) Start() error {
	return nil
}
func (router *Router) Close() error {
	router.stopFunc()
	return nil
}
