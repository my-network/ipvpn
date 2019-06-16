package connector

import (
	"net"

	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/iface"
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

func (connector *connector) NewConnection(peerLocal, peerRemote iface.Peer) (net.Conn, error) {
	connector.logger.Debugf("negotiation starts: local:%v; remote:%v", peerLocal.GetIntAlias(), peerRemote.GetIntAlias())
	negotiationMsgLocal, negotiationMsgRemote, err := connector.negotiator.NegotiateWith(peerRemote.GetID())
	connector.logger.Debugf("negotiation ended: local:%v:%v; remote:%v:%v; err:%v", peerLocal.GetIntAlias(), negotiationMsgLocal, peerRemote.GetIntAlias(), negotiationMsgRemote, err)
	if negotiationMsgRemote == nil || string(negotiationMsgRemote.Protocol) == "" {
		return nil, ErrNotNegotiatedYet.Wrap()
	}
	if err != nil {
		return nil, errors.Wrap(err)
	}
	conn, err := connector.newConnection(peerLocal, peerRemote, negotiationMsgLocal, negotiationMsgRemote)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	return conn, nil
}

func (connector *connector) newConnection(
	peerLocal, peerRemote iface.Peer,
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
		proto,
		Endpoint{
			Port: negotiationMsgLocal.SourcePort,
		},
		Endpoint{
			Host: remoteHost,
			Port: negotiationMsgRemote.SourcePort,
		},
	)

	err := conn.Dial()
	if err != nil {
		return nil, errors.Wrap(err)
	}

	return conn, nil
}
