package router

import (
	"net"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/my-network/ipvpn/vpn"
)

type Router struct {
}

func NewRouter() *Router {
	return &Router{}
}

func (router *Router) Start(vpn *vpn.VPN) {
	vpn.AddUpperHandler(router)
}

func (router *Router) OnUpdateMyIP(ip net.IP) {

}

func (router *Router) OnPeerConnect(peerID peer.ID, chType vpn.ChannelType, ip net.IP) {

}

func (router *Router) OnPeerDisconnect(peerID peer.ID, chType vpn.ChannelType) {

}
