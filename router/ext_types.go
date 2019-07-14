package router

import (
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/my-network/ipvpn/helpers"
	"github.com/my-network/ipvpn/network"
	"github.com/my-network/ipvpn/vpn"
)

type Stream = network.Stream
type AddrInfo = network.AddrInfo
type ReconnectableStream = helpers.ReconnectableStream
type PeerID = peer.ID
type ChannelType = vpn.ChannelType

const (
	ChannelType_undefined = vpn.ChannelType_undefined
	ChannelTypeDirect     = vpn.ChannelTypeDirect
	ChannelTypeIPFS       = vpn.ChannelTypeIPFS
	ChannelTypeTunnel     = vpn.ChannelTypeTunnel
	ChannelTypeAutoRouted = vpn.ChannelTypeAutoRouted
)
