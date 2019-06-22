package connector

import (
	"net"

	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/models"
)

var (
	ErrNotNegotiatedYet = errors.UnknownProtocol.New("not negotiated, yet")
)

type connector struct {
	negotiator Negotiator
	logger     Logger
}

func New(negotiator Negotiator, logger Logger) *connector {
	return &connector{
		negotiator: negotiator,
		logger:     logger,
	}
}

func (connector *connector) NewConnection(peerLocal, peerRemote *models.PeerT) (conn net.Conn, err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	if peerRemote.LastSuccessfulNegotiationMessage.Local != nil && peerRemote.LastSuccessfulNegotiationMessage.Remote != nil {
		connector.logger.Debugf("try old negotiation messages: local:%v; remote:%v", peerLocal.GetIntAlias(), peerRemote.GetIntAlias())
		conn, err = connector.newConnection(
			peerLocal,
			peerRemote,
			peerRemote.LastSuccessfulNegotiationMessage.Local,
			peerRemote.LastSuccessfulNegotiationMessage.Remote,
		)
		if err == nil {
			return
		}
	}

	connector.logger.Debugf("negotiation starts: local:%v; remote:%v", peerLocal.GetIntAlias(), peerRemote.GetIntAlias())
	negotiationMsgLocal, negotiationMsgRemote, err := connector.negotiator.NegotiateWith(peerRemote.GetID())
	connector.logger.Debugf("negotiation ended: local:%v:%v; remote:%v:%v; err:%v", peerLocal.GetIntAlias(), negotiationMsgLocal, peerRemote.GetIntAlias(), negotiationMsgRemote, err)
	if negotiationMsgRemote == nil || string(negotiationMsgRemote.Protocol) == "" {
		return nil, ErrNotNegotiatedYet
	}
	if err != nil {
		return
	}
	connector.logger.Debugf("making a connection: local:%v; remote:%v", peerLocal.GetIntAlias(), peerRemote.GetIntAlias())
	return connector.newConnection(peerLocal, peerRemote, negotiationMsgLocal, negotiationMsgRemote)
}

func (connector *connector) newConnection(
	peerLocal, peerRemote *models.PeerT,
	negotiationMsgLocal, negotiationMsgRemote *models.NegotiationMessage,
) (net.Conn, error) {
	// This's actually a wrong method to detect if the remote host is in the same network with you.
	// It may be better to use broadcast requests or something else. But for now this is good enough :)
	// May be will be fixed in a further release.
	isRemoteInLocalNetwork := peerLocal.GetHost().String() == peerRemote.GetHost().String()
	var remoteHost net.IP

	if negotiationMsgLocal.Protocol != negotiationMsgRemote.Protocol {
		return nil, errors.ProtocolMismatch.New(negotiationMsgLocal.Protocol, negotiationMsgRemote.Protocol)
	}

	if isRemoteInLocalNetwork {
		remoteHost = negotiationMsgRemote.LocalAddress
	} else {
		remoteHost = peerRemote.GetHost()
	}

	var proto Protocol
	switch negotiationMsgLocal.Protocol {
	case models.ProtocolUDP:
		proto = protocolUDP
	default:
		return nil, errors.UnknownProtocol.New(negotiationMsgLocal.Protocol)
	}

	conn := NewConnection(
		connector.logger,
		proto,
		Endpoint{
			Port: negotiationMsgLocal.SourcePort,
		},
		Endpoint{
			Host: remoteHost,
			Port: negotiationMsgRemote.SourcePort,
		},
	)

	doDial := peerLocal.GetIntAlias() > peerRemote.GetIntAlias()
	if negotiationMsgLocal.RequireReverseDirection || negotiationMsgRemote.RequireReverseDirection {
		doDial = !doDial
	}

	var err error
	if doDial {
		err = errors.Wrap(conn.Dial())
	} else {
		err = errors.Wrap(conn.Listen())
	}
	if err != nil {
		return nil, errors.Wrap(err)
	}

	peerRemote.SetLastNegotiationPair(negotiationMsgLocal, negotiationMsgRemote)
	return conn, nil
}
