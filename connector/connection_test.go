package connector

import (
	"net"
	"testing"
)

func TestConnectionType(t *testing.T) {
	var conn net.Conn
	conn = *connection{}
	_ = conn
}
