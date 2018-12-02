package negotiator

import (
	"net/http"
	"time"
	"sync"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/network"
)

type API interface {
	GetNegotiationMessages(networkID, peerIDTo string) (int, map[string]models.NegotiationMessageT, error)
}

type GetPeerIDer interface {
	GetPeerID() string
}

type negotiator struct {
	locker      sync.Mutex
	api         API
	interval    time.Duration
	networkID   string
	getPeerIDer GetPeerIDer
	loggerError Logger
	msgMap      map[string]models.NegotiationMessageT
}

func New(interval time.Duration, api API, networkID string, getPeerIDer GetPeerIDer) *negotiator {
	n := &negotiator{
		api:         api,
		interval:    interval,
		networkID:   networkID,
		getPeerIDer: getPeerIDer,
		loggerError: &errorLogger{},
		msgMap:      map[string]models.NegotiationMessageT{},
	}

	go n.fetchNegotiationMessagesLoop()
	return n
}

func (n *negotiator) LockDo(fn func()) {
	n.locker.Lock()
	defer n.locker.Lock()
	fn()
}

func (n *negotiator) fetchNegotiationMessagesLoop() {
	ticker := time.NewTicker(n.interval)
	for {
		<-ticker.C
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

		n.LockDo(func() {
			n.msgMap = msgMap
		})
	}
}

func (n *negotiator) GetNegotiatorMessage(peerIDTo, peerIDFrom string) (msg *models.NegotiationMessageT, err error) {
	n.LockDo(func() {
		msg = &[]models.NegotiationMessageT{n.msgMap[peerIDFrom]}[0]
	})
	if msg == nil {
		err = network.ErrNotReady
	}
	return
}
