package vpn

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"

	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/tenus"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/network"
)

const (
	TAPFrameMaxSize = 1500
)

var (
	ErrWrongMask = errors.New("Invalid mask")
)

type vpn struct {
	network         atomic.Value
	oldPeerIntAlias uint32
	closeChan       chan struct{}
	tapIface        *water.Interface
	tapLink         tenus.Linker
	subnet          net.IPNet
	locker          sync.Mutex
}

func New(subnet net.IPNet, homenet network.Network) (r *vpn, err error) {
	r = &vpn{
		subnet: subnet,
	}

	r.tapIface, err = water.New(water.Config{
		DeviceType: water.TAP,
	})
	if err != nil {
		return
	}
	r.tapLink, err = tenus.NewLinkFrom(r.tapIface.Name())
	if err = r.tapLink.SetLinkUp(); err != nil {
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

func (vpn *vpn) OnHomenetUpdatePeers(peers models.Peers) error {
	return vpn.updatePeers(peers)
}

func (vpn *vpn) setNetwork(newNetwork network.Network) {
	vpn.LockDo(func() {
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
	framebuf.Resize(TAPFrameMaxSize)

	type readChanMsg struct {
		n   int
		err error
	}
	readChan := make(chan readChanMsg)
	go func() {
		for vpn.GetNetwork() != nil {
			n, err := vpn.tapIface.Read([]byte(framebuf)) // TODO: check if this request will be unblocked on vpn.tapIface.Close()
			readChan <- readChanMsg{
				n:   n,
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

		dstMAC := macSlice(frame.Destination())
		if dstMAC.IsHomenet() {
			if !dstMAC.IsBroadcast() {
				continue
			}
		}
		logrus.Printf("Dst: %s\n", frame.Destination())
		logrus.Printf("Src: %s\n", frame.Source())
		logrus.Printf("Ethertype: % x\n", frame.Ethertype())
		logrus.Printf("Payload: % x\n", frame.Payload())
	}
}

func (vpn *vpn) Close() {
	vpn.LockDo(func() {
		vpn.setNetwork(nil)
		vpn.tapIface.Close()
		vpn.closeChan <- struct{}{}
	})
}

func (vpn *vpn) updateMAC(peerIntAlias uint32) error {
	newMAC := GenerateHomenetMAC(peerIntAlias)

	if err := vpn.tapLink.SetLinkMacAddress(newMAC.String()); err != nil {
		return errors.Wrap(err)
	}

	return nil
}

func (vpn *vpn) updateIPAddress(peerIntAlias uint32) error {
	maskOnes, maskBits := vpn.subnet.Mask.Size()
	if peerIntAlias >= 1<<uint32(maskBits-maskOnes) {
		return errors.Wrap(ErrWrongMask)
	}

	myAddress := vpn.subnet.IP
	if uint32(myAddress[len(myAddress)-1])+peerIntAlias > 255 {
		return fmt.Errorf("Not implemented yet: we can only modify the last octet at the moment")
	}
	myAddress[len(myAddress)-1] += uint8(peerIntAlias)

	if err := vpn.tapLink.SetLinkIp(myAddress, &vpn.subnet); err != nil {
		return errors.Wrap(err)
	}

	return nil
}

func (vpn *vpn) updatePeerIntAlias(newPeerIntAlias uint32) error {
	if err := vpn.updateMAC(newPeerIntAlias); err != nil {
		return errors.Wrap(err)
	}

	if err := vpn.updateIPAddress(newPeerIntAlias); err != nil {
		return errors.Wrap(err)
	}

	if err := vpn.tapLink.SetLinkUp(); err != nil {
		return errors.Wrap(err)
	}

	vpn.oldPeerIntAlias = newPeerIntAlias
	return nil
}

func (vpn *vpn) updatePeers(peers models.Peers) error {
	peerIntAlias := vpn.GetPeerIntAlias()

	if vpn.oldPeerIntAlias != peerIntAlias {
		if err := vpn.updatePeerIntAlias(peerIntAlias); err != nil {
			return errors.Wrap(err)
		}
	}

	return nil
}

func (vpn *vpn) GetPeerID() string {
	return vpn.GetNetwork().GetPeerID()
}

func (vpn *vpn) GetPeerIntAlias() uint32 {
	return vpn.GetNetwork().GetPeerIntAlias()
}
