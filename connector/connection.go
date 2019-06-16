package connector

import (
	"net"
	"time"

	"github.com/xaionaro-go/errors"
)

const (
	tryIterationInterval = time.Second

	segmentSize = 1000
	bufSize     = segmentSize + 100
)

type Protocol string

const (
	protocolUDP = Protocol("udp")
)

func (proto Protocol) String() string {
	return string(proto)
}

type Connection struct {
	net.Conn

	protocol    Protocol
	source      Endpoint
	destination Endpoint
}

type Endpoint struct {
	Port uint16
	Host net.IP
}

func NewConnection(protocol Protocol, source, destination Endpoint) *Connection {
	return &Connection{
		protocol:    protocol,
		source:      source,
		destination: destination,
	}
}

func (conn *Connection) startListening() error {
	switch conn.protocol {
	case protocolUDP:
		return nil
	}
	return errors.NotImplemented.New(conn.protocol)
}

func (conn *Connection) Dial() (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	if err := conn.startListening(); err != nil {
		return errors.Wrap(err)
	}

	switch conn.protocol {
	case protocolUDP:
		var realConn *net.UDPConn
		realConn, err = net.DialUDP(
			conn.protocol.String(),
			&net.UDPAddr{
				Port: int(conn.source.Port),
			},
			&net.UDPAddr{
				IP:   conn.destination.Host,
				Port: int(conn.destination.Port),
			},
		)

		if err != nil {
			return
		}

		if err = udpSetNoFragment(realConn); err != nil {
			return
		}

		conn.Conn = realConn
	default:
		return errors.NotImplemented.New(conn.protocol)
	}

	waitingForAnswer := true
	var err2 error
	go func() {
		for waitingForAnswer {
			if err := conn.SendEmptyPacket(); err != nil {
				err2 = errors.Wrap(err)
			}
			time.Sleep(tryIterationInterval)
		}
	}()
	_, err = conn.Read([]byte{})
	waitingForAnswer = false

	if err == nil {
		err = err2
	}
	return err
}

func (conn *Connection) SendEmptyPacket() error {
	_, err := conn.Write([]byte{})
	return err
}

func (conn *Connection) WaitForEmptyPacket() error {

	_, err := conn.Read([]byte{})
	return err
}

func (conn *Connection) Close() error {
	if err := conn.Conn.Close(); err != nil {
		return err
	}
	conn.Conn = nil
	return nil
}
