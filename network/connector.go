package network

import (
	"net"

	"github.com/xaionaro-go/homenet-server/iface"
)

type Connector interface {
	NewConnection(peerLocal, peerRemote iface.Peer) (net.Conn, error)
}
