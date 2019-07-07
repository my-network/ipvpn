// +build linux darwin freebsd openbsd netbsd

package vpn

import (
	"golang.org/x/sys/unix"
	"net"
	"syscall"
	"time"

	"github.com/xaionaro-go/errors"
)

func dialUDPReuse(net string, laddr, raddr *net.UDPAddr) (conn *udpClientSocket, err error) {
	defer func() { err = errors.Wrap(err) }()

	var clientSock int
	if clientSock, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP); err != nil {
		return
	}

	if err = udpSetReuseFD(clientSock); err != nil {
		return
	}

	var remoteAddr syscall.SockaddrInet4
	raddrIP := raddr.IP.To4()
	remoteAddr.Addr = [4]byte{raddrIP[0], raddrIP[1], raddrIP[2], raddrIP[3]}
	remoteAddr.Port = raddr.Port

	err = syscall.Bind(clientSock, &syscall.SockaddrInet4{
		Port: laddr.Port,
	})

	if err = syscall.Connect(clientSock, &remoteAddr); err != nil {
		return
	}

	conn = &udpClientSocket{clientSock, laddr, raddr}
	return
}

type udpClientSocket struct {
	fd         int
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
}

func (udpConn *udpClientSocket) Read(b []byte) (int, error) {
	return syscall.Read(udpConn.fd, b)
}

func (udpConn *udpClientSocket) Write(b []byte) (int, error) {
	return syscall.Write(udpConn.fd, b)
}

func (udpConn *udpClientSocket) Close() error {
	return syscall.Close(udpConn.fd)
}

func (udpConn *udpClientSocket) RemoteAddr() net.Addr {
	return udpConn.remoteAddr
}

func (udpConn *udpClientSocket) LocalAddr() net.Addr {
	return udpConn.localAddr
}

func (udpConn *udpClientSocket) SetDeadline(t time.Time) error {
	return errors.NotImplemented
}
func (udpConn *udpClientSocket) SetReadDeadline(t time.Time) error {
	return errors.NotImplemented
}
func (udpConn *udpClientSocket) SetWriteDeadline(t time.Time) error {
	return errors.NotImplemented
}

func udpSetReuseFD(fd int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return nil
}
