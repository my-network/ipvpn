package vpn

import (
	"net"
	"sync"
)

type WGNet struct {
	locker         sync.RWMutex
	currentIP      net.IP
	Subnet         net.IPNet
	IfaceName      string
	WGListenerAddr net.UDPAddr
}
