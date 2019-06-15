package connector

import (
	"io"
	"net"

	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/iface"

	"github.com/xaionaro-go/homenet-peer/filters"
)

type connector struct {
	negotiator Negotiator
}

func New(negotiator Negotiator) *connector {
	return &connector{
		negotiator: negotiator,
	}
}

func (connector *connector) NewConnection(peerLocal, peerRemote iface.Peer, filters ...filters.Filter) (net.Conn, error) {
	negotiationMsgLocal, negotiationMsgRemote, err := connector.negotiator.NegotiateWith(peerRemote.GetID())
	if err != nil {
		return nil, errors.Wrap(err)
	}
	conn, err := connector.newConnection(peer, negotiationMsgLocal, negotiationMsgRemote, filters)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	return conn, nil
}

func (connector *connector) newConnection(peerLocal, peerRemote iface.Peer, negotiationMsgLocal, negotiationMsgRemote iface.NegotiationMessage, filters []filters.Filter) (net.Conn, error) {
	// This's actually a wrong method to detect if the remote host is in the same network with you.
	// It may be better to use broadcast requests or something else. But for now this is good enough :)
	// May be will be fixed in a further release.
	isRemoteInLocalNetwork := peerLocal.GetHost() == peerRemote.GetHost()
	var remoteHost net.IP

	if negotiationMsgLocal.GetProtocol() != negotiationMsgRemote.GetProtocol() {
		return errors.ProtocolMismatch.New(negotiationMsgLocal.GetProtocol(), negotiationMsgRemote.GetProtocol())
	}

	if isRemoteInLocalNetwork {
		remoteHost = negotiationMsgRemote.GetLocalAddress()
	} else {
		remoteHost = peerRemote.GetHost()
	}

	var proto Protocol
	switch negotiationMsgLocal.GetProtocol() {
	case "udp":
		proto = protocolUDP
	default:
		return nil, errors.UnknownProtocol.New(negotiationMsgLocal.GetProtocol())
	}

	conn := NewConnection(
		proto,
		endpoint {
			port: negotiationMsgLocal.GetSourcePort(),
		},
		endpoint {
			host: remoteHost,
			port: negotiationMsgRemote.GetSourcePort(),
		},
		filters...
	)

	err := conn.Dial()
	if err != nil {
		return nil, err
	}

	return conn, nil
}
