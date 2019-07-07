package network

import (
	"context"
	"github.com/my-network/ipvpn/helpers"
	"math"
	"net"
	"time"

	p2pcore "github.com/libp2p/go-libp2p-core"
	"github.com/multiformats/go-multiaddr"
)

func (mesh *Network) measureLatencyToMultiaddr(ctx context.Context, addr p2pcore.Multiaddr) time.Duration {
	portStr, err := addr.ValueForProtocol(multiaddr.P_TCP)
	if err != nil {
		portStr, err = addr.ValueForProtocol(multiaddr.P_UDP)
	}
	if err != nil {
		mesh.logger.Debugf("unable to get TCP/UDP port from multiaddress \"%v\": %v", addr.String(), err)
		return math.MaxInt64
	}
	if portStr != ipfsPortString {
		mesh.logger.Debugf("NAT-ed port, seems to be unreachable: %v", addr.String())
		return math.MaxInt64 / 4
	}
	for _, streamHandler := range mesh.streamHandlers {
		if streamHandler.IsBadAddress(addr) {
			mesh.logger.Debugf("a streamHandler said it's a bad address: %v", addr.String())
			return math.MaxInt64
		}
	}

	addr4, err := addr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		mesh.logger.Debugf("unable to get IPv4 address from multiaddress \"%v\": %v", addr.String(), err)
		return math.MaxInt64
	}

	return helpers.MeasureLatency(ctx, net.ParseIP(addr4), mesh.logger)
}
