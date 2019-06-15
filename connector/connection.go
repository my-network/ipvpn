package connector

import (
	"net"
	"io"
	"time"

	"github.com/xaionaro-go/errors"
)

const (
	tryIterationInterval = time.Second

	segmentSize = 1000
	bufSize = segmentSize + 100
)

type Protocol string

const (
	protocolUDP = Protocol("udp")
)

func (proto Protocol) String() string {
	return string(proto)
}

type Filter interface {
	WrapReader(io.Reader) io.Reader
	WrapWriter(io.Writer) io.Writer
}

type connection struct {
	protocol Protocol
	source Endpoint
	destination Endpoint
	filters []Filter

	rawConnection net.Conn
	reader io.Reader
	writer io.Writer
}

type Endpoint struct {
	Port uint16
	Host net.IP
}

func NewConnection(protocol Protocol, source, destination Endpoint, filters ...Filter) *connection {
	return &connection{
		protocol: protocol,
		source: source,
		destination: destination,
		filters: filters,
	}
}

func (conn *connection) startListening() error {
	switch conn.protocol {
		case protocolUDP:
			return nil
	}
	return errors.NotImplemented.New(conn.protocol)
}

func (conn *connection) Dial() error {
	if err := conn.startListening(); err != nil {
		return errors.Wrap(err)
	}

	var err error
	switch conn.protocol {
	case protocolUDP:
		conn.rawConnection, err = net.DialUDP(
			conn.protocol.String(),
			&net.UDPAddr{
				Port: int(conn.source.Port),
			},
			&net.UDPAddr{
				IP:   conn.destination.Host,
				Port: int(conn.destination.Port),
			},
		)
	default:
		return errors.NotImplemented.New(conn.protocol)
	}

	if err != nil {
		return errors.Wrap(err)
	}

	if err := conn.prepareReadWriter(); err != nil {
		return errors.Wrap(err)
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

func (conn *connection) prepareReadWriter() error {
	var reader io.Reader
	reader = conn.rawConnection
	for _, filter := range conn.filters {
		reader = filter.WrapReader(reader)
	}
	conn.reader = reader

	var writer io.Writer
	writer = conn.rawConnection
	for _, filter := range conn.filters {
		writer = filter.WrapWriter(writer)
	}
	conn.writer = writer

	return nil
}

func (conn *connection) SendEmptyPacket() error {
	_, err := conn.Write([]byte{})
	return err
}

func (conn *connection) WaitForEmptyPacket() error {
	
	_, err := conn.Read([]byte{})
	return err
}

func (conn *connection) Write(b []byte) (int, error) {
	return conn.writer.Write(b)
}

func (conn *connection) Read(b []byte) (int, error) {
	return conn.reader.Read(b)
}

func (conn *connection) Close() error {
	if err := conn.rawConnection.Close(); err != nil {
		return err
	}
	conn.rawConnection = nil
	conn.reader = nil
	conn.writer = nil
	return nil
}
