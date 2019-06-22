package network

import (
	"net"

	"github.com/xaionaro-go/homenet-server/models"
)

type Connector interface {
	NewConnection(peerLocal, peerRemote *models.PeerT) (net.Conn, error)
}
