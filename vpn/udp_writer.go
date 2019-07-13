package vpn

import (
	"io"
	"net"

	"github.com/xaionaro-go/errors"
)

type udpWriter struct {
	*net.UDPConn
	addr       *net.UDPAddr
	readCloser io.ReadCloser
}

func newUDPWriter(conn *net.UDPConn, readCloser io.ReadCloser, addr *net.UDPAddr) *udpWriter {
	return &udpWriter{
		UDPConn:    conn,
		addr:       addr,
		readCloser: readCloser,
	}
}

func (w *udpWriter) Write(b []byte) (size int, err error) {
	size, err = w.UDPConn.WriteToUDP(b, w.addr)
	if err != nil {
		err = errors.Wrap(err)
	}
	return
}

func (w *udpWriter) Read(b []byte) (size int, err error) {
	return w.readCloser.Read(b)
}

func (w *udpWriter) Close() error {
	return w.readCloser.Close()
}
