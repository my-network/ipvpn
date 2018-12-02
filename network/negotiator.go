package network

import (
	"github.com/xaionaro-go/homenet-server/models"
)

type Negotiator interface {
	GetNegotiatorMessage(peerIDTo, peerIDFrom string) (*models.NegotiationMessageT, error)
}
