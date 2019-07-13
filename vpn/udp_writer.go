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

func (w *udpWriter) WriteToUDP(b []byte, addr *net.UDPAddr) (size int, err error) {
	size, err = w.UDPConn.WriteToUDP(b, addr)
	if err != nil {
		err = errors.Wrap(err)
	}
	return
}

func (w *udpWriter) Read(b []byte) (size int, err error) {
	size, err = w.readCloser.Read(b)
	if err != nil {
		err = errors.Wrap(err)
	}
	return
}

func (w *udpWriter) ReadFromUDP(b []byte) (size int, addr *net.UDPAddr, err error) {
	readFromUDPer := w.readCloser.(interface {
		ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	})
	size, addr, err = readFromUDPer.ReadFromUDP(b)
	if err != nil {
		err = errors.Wrap(err)
	}
	return
}

func (w *udpWriter) Close() (err error) {
	err = w.readCloser.Close()
	if err != nil {
		err = errors.Wrap(err)
	}
	return err
}
