package negotiator

import (
	"net/http"
	"sync"
	"time"

	"github.com/xaionaro-go/errors"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/network"
)

type API interface {
	GetNegotiationMessages(networkID, peerIDTo string) (int, map[string]models.NegotiationMessageT, error)
	GetNegotiationMessage(networkID, peerIDTo, peerIDFrom string) (int, *models.NegotiationMessageT, error)
	SetNegotiationMessage(networkID, peerIDTo, peerIDFrom string, msg *models.NegotiationMessageT) (int, *models.NegotiationMessageT, error)
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
	loggerError Logger
	msgMap      map[string]models.NegotiationMessageT
	stopChan    chan struct{}
}

func New(interval time.Duration, api API, networkID string, getPeerIDer GetPeerIDer) *Negotiator {
	n := &Negotiator{
		api:         api,
		interval:    interval,
		networkID:   networkID,
		getPeerIDer: getPeerIDer,
		loggerError: &errorLogger{},
		msgMap:      map[string]models.NegotiationMessageT{},
		stopChan:    make(chan struct{}),
	}

	go n.fetchNegotiationMessagesLoop()
	return n
}

func (n *Negotiator) lockDo(fn func()) {
	n.locker.Lock()
	defer n.locker.Lock()
	fn()
}

func (n *Negotiator) fetchNegotiationMessagesLoop() {
	ticker := time.NewTicker(n.interval)
	for {
		select {
		case <-n.stopChan:
			close(n.stopChan)
			return
		case <-ticker.C:
		}
		httpCode, msgMap, err := n.api.GetNegotiationMessages(n.networkID, n.getPeerIDer.GetPeerID())
		if err != nil {
			n.loggerError.Printf("%v", err)
			continue
		}
		switch httpCode {
		case http.StatusOK:
		default:
			n.loggerError.Printf("Unexpected HTTP code: %v", httpCode)
			continue
		}

		n.lockDo(func() {
			n.msgMap = msgMap
		})
	}
}

func (n *Negotiator) GetNegotiationMessage(peerIDTo, peerIDFrom string) (msg *models.NegotiationMessageT, err error) {
	n.lockDo(func() {
		msg = &[]models.NegotiationMessageT{n.msgMap[peerIDFrom]}[0]
	})
	if msg == nil {
		err = network.ErrNotReady
	}
	return
}

func (n *Negotiator) SetNegotiationMessage(peerIDTo, peerIDFrom string, msg *models.NegotiationMessageT) error {
	status, _, err := n.api.SetNegotiationMessage(n.networkID, peerIDTo, peerIDFrom, msg)
	if err != nil {
		return errors.Wrap(err)
	}
	if status != 200 {
		return errors.UnexpectedHTTPStatusCode.Wrap(status)
	}
	return nil
}

func (n *Negotiator) NegotiateWith(peerIDTo string) (localMsg *models.NegotiationMessageT, remoteMsg *models.NegotiationMessageT, err error) {
	n.lockDo(func() {
		localMsg = &[]models.NegotiationMessageT{n.msgMap[n.getPeerIDer.GetPeerID()]}[0]
		remoteMsg = &[]models.NegotiationMessageT{n.msgMap[peerIDTo]}[0]
	})
	return
}

func (n *Negotiator) Stop() {
	n.stopChan <- struct{}{}
}
