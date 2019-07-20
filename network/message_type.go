package network

type MessageType uint8

const (
	MessageTypeUndefined = MessageType(iota)
	MessageTypeOK
	MessageTypeStopConnectionOnYourSide
	MessageTypeDontReconnect
	MessageTypeCustom
)
