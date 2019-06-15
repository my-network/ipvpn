package connector

import (
	"github.com/xaionaro-go/homenet-server/iface"
)

type Negotiator interface {
	NegotiateWith(peerIDTo string) (iface.NegotiationMessage, iface.NegotiationMessage, error)
}
