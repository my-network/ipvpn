package vpn

import (
	"encoding/binary"
)

type MessageType uint16

const (
	MessageTypeUndefined = MessageType(iota)
	MessageTypePing
	MessageTypePong
	MessageTypeIntAlias
	MessageTypeEnscapsulated
	MessageTypeConfig
)

var (
	sizeOfMessageType = binary.Size(MessageTypePing)
)

func (t MessageType) String() string {
	switch t {
	case MessageTypeUndefined:
		return `undefined`
	case MessageTypePing:
		return `ping`
	case MessageTypePong:
		return `pong`
	case MessageTypeIntAlias:
		return `int_alias`
	case MessageTypeEnscapsulated:
		return `encapsulated`
	case MessageTypeConfig:
		return `config`
	default:
		return `unknown`
	}
}

func (t MessageType) Write(b []byte) (n int, err error) {
	binary.LittleEndian.PutUint16(b, uint16(t))
	return 2, nil
}

func ReadMessageType(b []byte) MessageType {
	return MessageType(binary.LittleEndian.Uint16(b))
}
