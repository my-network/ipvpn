package vpn

type MessageType uint16

const (
	MessageTypeUndefined = MessageType(iota)
	MessageTypeConfig
	MessageTypePacket
)
