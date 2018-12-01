package vpn

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/network"
)

const (
	tapFrameMaxSize = 1500
)

type vpn struct {
	network   atomic.Value
	closeChan chan struct{}
	tapIface  *water.Interface
	locker    sync.Mutex
}

func New(homenet network.Network) (r *vpn, err error) {
	r = &vpn{}

	r.tapIface, err = water.New(water.Config{
		DeviceType: water.TAP,
	})
	if err != nil {
		return
	}
	r.setNetwork(homenet)

	go r.tapReadHandler()
	return
}

func (vpn *vpn) LockDo(fn func()) {
	vpn.locker.Lock()
	defer vpn.locker.Unlock()
	fn()
}

func (vpn *vpn) OnHomenetClose() {
	vpn.Close()
}

func (vpn *vpn) OnHomenetUpdatePeers(models.Peers) error {
	return nil
}

func (vpn *vpn) setNetwork(newNetwork network.Network) {
	vpn.LockDo(func(){
		oldNetwork := vpn.GetNetwork()
		if oldNetwork != nil {
			oldNetwork.RemoveHooker(vpn)
		}

		vpn.network.Store(newNetwork)

		newNetwork.AddHooker(vpn)
	})
}

func (vpn *vpn) GetNetwork() network.Network {
	net := vpn.network.Load()
	if net == nil {
		return nil
	}
	return net.(network.Network)
}

func (vpn *vpn) tapReadHandler() {
	var framebuf ethernet.Frame
	framebuf.Resize(tapFrameMaxSize)

	type readChanMsg struct {
		n int
		err error
	}
	readChan := make(chan readChanMsg)
	go func() {
		for vpn.GetNetwork() != nil {
			n, err := vpn.tapIface.Read([]byte(framebuf)) // TODO: check if this request will be unblocked on vpn.tapIface.Close()
			readChan <- readChanMsg{
				n: n,
				err: err,
			}
		}
	}()
	for vpn.GetNetwork() != nil {
		var msg readChanMsg
		select {
		case <-vpn.closeChan:
			return
		case msg = <-readChan:
		}
		if msg.err != nil {
			logrus.Errorf("Unable to read from %s: %s", vpn.tapIface.Name(), msg.err)
			time.Sleep(time.Second)
		}
		frame := framebuf[:msg.n]
		logrus.Printf("Dst: %s\n", frame.Destination())
		logrus.Printf("Src: %s\n", frame.Source())
		logrus.Printf("Ethertype: % x\n", frame.Ethertype())
		logrus.Printf("Payload: % x\n", frame.Payload())
	}
}

func (vpn *vpn) Close() {
	vpn.setNetwork(nil)
	vpn.tapIface.Close()
	vpn.closeChan <- struct{}{}
}

func (vpn *vpn) updatePeers(peers models.Peers) error {
	return nil
}

func (vpn *vpn) GetPeerID() string {
	return vpn.GetNetwork().GetPeerID()
}
