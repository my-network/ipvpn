package vpn

import (
	"net"

	"github.com/libp2p/go-libp2p-core/peer"
)

type UpperHandler interface {
	OnUpdateMyIP(ip net.IP)
	OnPeerConnect(peerID peer.ID, chType ChannelType, ip net.IP)
	OnPeerDisconnect(peerID peer.ID, chType ChannelType)
}
