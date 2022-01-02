//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd
// +build !linux,!darwin,!freebsd,!openbsd,!netbsd

package vpn

import (
	"net"
)

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	return
}

func udpSetNoFragmentSyscall(conn *udpClientSocket) (err error) {
	return
}

func udpSetReuseFD(fd int) error {
	return
}
