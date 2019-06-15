package network

import (
	"net"

	"github.com/xaionaro-go/homenet-server/iface"

	"github.com/xaionaro-go/homenet-peer/filters"
)

type Connector interface {
	NewConnection(peerLocal, peerRemote iface.Peer, filters ...filters.Filter) (net.Conn, error)
}
