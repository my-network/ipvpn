// +build !linux

package connector

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	return nil
}
