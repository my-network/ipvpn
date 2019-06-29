// +build !linux

package vpn

import (
	"net"
)

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	return nil
}
