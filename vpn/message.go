package vpn

type MessageType uint16

const (
	MessageTypeUndefined = MessageType(iota)
	MessageTypePing
	MessageTypePong
	MessageTypeConfig
	MessageTypePacket
)
