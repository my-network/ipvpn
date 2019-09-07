package helpers

import (
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
)

type AddrInfo = peer.AddrInfo

func CopyAddrInfo(addrInfo AddrInfo) *AddrInfo {
	addrs := make([]multiaddr.Multiaddr, len(addrInfo.Addrs))
	copy(addrs, addrInfo.Addrs)
	addrInfo.Addrs = addrs
	return &addrInfo
}
