// +build !linux

package vpn

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	return nil
}
