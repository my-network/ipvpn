package router

import (
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/my-network/ipvpn/helpers"
	"github.com/xaionaro-go/atomicmap"
	"golang.org/x/crypto/ed25519"
	"net"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/ipvpn/vpn"
)

const (
	routerProtocolID = protocol.ID(`/p2p/github.com/my-network/ipvpn/router`)
)

type Router struct {
	mesh           *network.Network
	logger         Logger
	streamIngoing  atomicmap.Map
	streamOutgoing atomicmap.Map
}

func NewRouter(logger Logger) *Router {
	return &Router{
		logger:         logger,
		streamIngoing:  atomicmap.New(),
		streamOutgoing: atomicmap.New(),
	}
}

func (router *Router) ProtocolID() protocol.ID {
	return routerProtocolID
}

func (router *Router) SetNetwork(mesh *network.Network) {
	router.mesh = mesh
}

func (router *Router) OnUpdateMyIP(ip net.IP) {

}

func (router *Router) OnPeerConnect(peerID peer.ID, chType vpn.ChannelType, ip net.IP) {
	go router.createOutgoingStreamIfNotExists(peerID)
	go router.considerNewRoute(peerID, chType, ip)
}

func (router *Router) createOutgoingStreamIfNotExists(peerID peer.ID) {
	if streamI, _ := router.streamOutgoing.Get(peerID); streamI != nil {
		return
	}

	stream := helpers.NewReconnectableStream(router.logger, func() (Stream, error) {
		return router.mesh.NewStream(peerID, router.ProtocolID())
	})
	if oldStreamI, _ := router.streamOutgoing.Swap(peerID, stream); oldStreamI != nil {
		oldStream := oldStreamI.(Stream)
		_ = oldStream.Close()
	}
}

func (router *Router) considerNewRoute(peerID peer.ID, chType vpn.ChannelType, ip net.IP) {
}

func (router *Router) NewStream(stream Stream, peerAddr AddrInfo) {

}

func (router *Router) OnPeerDisconnect(peerID peer.ID, chType vpn.ChannelType) {

}

func (router *Router) ConsiderKnownPeer(peerAddr AddrInfo) {

}

func (router *Router) SetID(id peer.ID) {

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
	return nil
}
