package vpn

import (
	"encoding/binary"
)

type MessageType uint16

const (
	MessageTypeUndefined = MessageType(iota)
	MessageTypePing
	MessageTypePong
	MessageTypeConfig
	MessageTypePacket
)

var (
	sizeOfMessageType = binary.Size(MessageTypePing)
)
