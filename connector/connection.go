package connector

import (
	"net"
	"time"

	"github.com/xaionaro-go/errors"
)

const (
	connectionWaitTimeout = time.Second * 20
	tryIterationInterval  = time.Second

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

	logger      Logger
	protocol    Protocol
	source      Endpoint
	destination Endpoint
}

type Endpoint struct {
	Port uint16
	Host net.IP
}

func NewConnection(logger Logger, protocol Protocol, source, destination Endpoint) *Connection {
	return &Connection{
		logger:      logger,
		protocol:    protocol,
		source:      source,
		destination: destination,
	}
}

func (conn *Connection) Listen() (err error) {
	conn.logger.Debugf("(*Connection).Listen()")
	defer func() {
		err = errors.Wrap(err)
		conn.logger.Debugf("/(*Connection).Listen(): %v", err)
	}()
	switch conn.protocol {
	case protocolUDP:
		conn.Conn, err = conn.dialUDP()
	default:
		return errors.NotImplemented.Wrap(conn.protocol)
	}
	if err != nil {
		return
	}

	err = conn.waitForConnection()
	if err != nil {
		_ = conn.Close()
	}
	return
}

func (conn *Connection) Dial() (err error) {
	conn.logger.Debugf("(*Connection).Dial()")
	defer func() {
		err = errors.Wrap(err)
		conn.logger.Debugf("/(*Connection).Dial(): %v", err)
	}()

	switch conn.protocol {
	case protocolUDP:
		conn.Conn, err = conn.dialUDP()
	default:
		return errors.NotImplemented.New(conn.protocol)
	}
	if err != nil {
		return
	}

	err = conn.waitForConnection()
	if err != nil {
		_ = conn.Close()
	}
	return
}

func (conn *Connection) dialUDP() (c *net.UDPConn, err error) {
	conn.logger.Debugf("(*Connection).dialUDP()")
	defer func() {
		err = errors.Wrap(err)
		conn.logger.Debugf("/(*Connection).dialUDP(): %v", err)
	}()

	c, err = net.DialUDP(
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

	if err = udpSetNoFragment(c); err != nil {
		return
	}

	return
}

func (conn *Connection) waitForConnection() (err error) {
	conn.logger.Debugf("(*Connection).waitForConnection()")
	defer func() {
		err = errors.Wrap(err)
		conn.logger.Debugf("/(*Connection).waitForConnection(): %v", err)
	}()

	waitingForAnswer := true
	go func() {
		err = conn.WaitForEmptyPacket()
		waitingForAnswer = false
	}()

	var err2 error
	start := time.Now()
	for waitingForAnswer && time.Since(start) < connectionWaitTimeout {
		if err2 = errors.Wrap(conn.SendEmptyPacket()); err2 != nil {
			break
		}
		time.Sleep(tryIterationInterval)
	}

	if err == nil {
		err = err2
	}
	return err
}

func (conn *Connection) SendEmptyPacket() error {
	conn.logger.Debugf("(*Connection).SendEmptyPacket()")
	_, err := conn.Write([]byte{})
	return err
}

func (conn *Connection) WaitForEmptyPacket() error {
	conn.logger.Debugf("(*Connection).WaitForEmptyPacket()")
	_, err := conn.Read([]byte{})
	return err
}

func (conn *Connection) Close() error {
	conn.logger.Debugf("(*Connection).Close()")
	if err := conn.Conn.Close(); err != nil {
		return err
	}
	conn.Conn = nil
	return nil
}
