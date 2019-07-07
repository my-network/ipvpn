// +build linux

package vpn

import (
	"net"
	"syscall"

	"github.com/xaionaro-go/errors"
)

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	defer func() { err = errors.Wrap(err) }()
	var syscallConn syscall.RawConn
	syscallConn, err = conn.SyscallConn()
	if err != nil {
		return
	}
	err2 := errors.Wrap(syscallConn.Control(func(fd uintptr) {
		err = errors.Wrap(syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO))
	}))
	if err != nil {
		return
	}
	err = err2
	return
}

func udpSetNoFragmentSyscall(conn *udpClientSocket) (err error) {
	if err = syscall.SetsockoptByte(int(conn.fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); err != nil {
		return
	}

	return
}
