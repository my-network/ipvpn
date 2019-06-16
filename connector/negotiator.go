package connector

import (
	"github.com/xaionaro-go/homenet-server/models"
)

type Negotiator interface {
	NegotiateWith(peerIDTo string) (*models.NegotiationMessage, *models.NegotiationMessage, error)
}
