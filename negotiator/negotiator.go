package negotiator

import (
	"net/http"
	"sync"
	"time"

	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/network"
)

const (
	negotiationTimeout = time.Second * 15
)

type API interface {
	GetNegotiationMessages(networkID, peerIDTo string) (int, map[string]models.NegotiationMessage, error)
	GetNegotiationMessage(networkID, peerIDTo, peerIDFrom string) (int, *models.NegotiationMessage, error)
	SetNegotiationMessage(networkID, peerIDTo, peerIDFrom string, msg *models.NegotiationMessage) (int, *models.NegotiationMessage, error)
}

type GetPeerIDer interface {
	GetPeerID() string
}

type Negotiator struct {
	locker      sync.Mutex
	api         API
	interval    time.Duration
	networkID   string
	getPeerIDer GetPeerIDer
	logger      Logger
	msgMap      map[string]models.NegotiationMessage
	stopChan    chan struct{}
}

func New(interval time.Duration, api API, networkID string, getPeerIDer GetPeerIDer, logger Logger) *Negotiator {
	n := &Negotiator{
		api:         api,
		interval:    interval,
		networkID:   networkID,
		getPeerIDer: getPeerIDer,
		logger:      logger,
		msgMap:      map[string]models.NegotiationMessage{},
		stopChan:    make(chan struct{}),
	}

	go n.fetchNegotiationMessagesLoop()
	return n
}

func (n *Negotiator) lockDo(fn func()) {
	n.locker.Lock()
	defer n.locker.Unlock()
	fn()
}

func (n *Negotiator) fetchNegotiationMessages() map[string]models.NegotiationMessage {
	n.logger.Debugf("fetching new negotiation messages")
	httpCode, msgMap, err := n.api.GetNegotiationMessages(n.networkID, n.getPeerIDer.GetPeerID())
	n.logger.Debugf("endof <fetching new negotiation messages>: %v %v %v", httpCode, err, msgMap)
	if err != nil {
		n.logger.Error(err)
		return nil
	}
	switch httpCode {
	case http.StatusOK:
	default:
		n.logger.Error("Unexpected HTTP code:", httpCode)
		return nil
	}

	return msgMap
}

func (n *Negotiator) fetchNegotiationMessagesLoop() {
	n.lockDo(func() {
		n.msgMap = n.fetchNegotiationMessages()
	})
	ticker := time.NewTicker(n.interval)
	for {
		select {
		case <-n.stopChan:
			close(n.stopChan)
			return
		case <-ticker.C:
		}
		n.lockDo(func() {
			msgMap := n.fetchNegotiationMessages()
			if msgMap != nil {
				n.msgMap = msgMap
			}
		})
	}
}

func (n *Negotiator) GetNegotiationMessage(peerIDTo, peerIDFrom string) (msg *models.NegotiationMessage, err error) {
	n.lockDo(func() {
		msg = &[]models.NegotiationMessage{n.msgMap[peerIDFrom]}[0]
	})
	if msg == nil {
		err = network.ErrNotReady
	}
	return
}

func (n *Negotiator) SetNegotiationMessage(peerIDTo, peerIDFrom string, msg *models.NegotiationMessage) error {
	status, _, err := n.api.SetNegotiationMessage(n.networkID, peerIDTo, peerIDFrom, msg)
	if err != nil {
		return errors.Wrap(err)
	}
	if status != 200 {
		return errors.UnexpectedHTTPStatusCode.Wrap(status)
	}
	return nil
}

func (n *Negotiator) getProposal(peerIDTo string) *models.NegotiationMessage {
	return &models.NegotiationMessage{
		Protocol:     models.ProtocolUDP,
		SourcePort:   51476,
		LocalAddress: nil,
	}
}

func (n *Negotiator) NegotiateWith(peerIDTo string) (localMsg *models.NegotiationMessage, remoteMsg *models.NegotiationMessage, err error) {
	localMsg = n.getProposal(peerIDTo)
	err = n.SetNegotiationMessage(peerIDTo, n.getPeerIDer.GetPeerID(), localMsg)
	if err != nil {
		return
	}
	start := time.Now()
	n.lockDo(func() {
		remoteMsg = &[]models.NegotiationMessage{n.msgMap[peerIDTo]}[0]
	})
	if remoteMsg.Protocol != "" {
		return
	}
	iteration := uint(0)
	for {
		remoteMsg, err = n.GetNegotiationMessage(peerIDTo, n.getPeerIDer.GetPeerID())
		if remoteMsg.Protocol != "" || err != nil {
			return
		}
		if time.Since(start) > negotiationTimeout {
			return
		}
		time.Sleep(time.Second * time.Duration(1<<iteration))
		iteration++
	}
	return
}

func (n *Negotiator) Stop() {
	n.stopChan <- struct{}{}
}
