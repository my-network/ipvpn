package vpn

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	ErrWrongMask    = errors.New("Invalid mask")
	ErrPeerNotFound = errors.NotFound.New("peer not found")
	ErrNoPath       = errors.CannotSendData.New("there's no established path, yet")
	ErrPartialWrite = errors.New("partial write")
	ErrEmptyPayload = errors.New("empty payload")
)

type vpn struct {
	network         atomic.Value
	oldPeerIntAlias uint32
	closeChan       chan struct{}
	tapIface        *water.Interface
	tapLink         tenus.Linker
	subnet          net.IPNet
	locker          sync.Mutex
	writerMap       map[string]io.Writer

	loggerError Logger
	loggerDump  Logger
}

func New(subnet net.IPNet, homenet *network.Network, opts ...Option) (r *vpn, err error) {
	defer func() {
		err = errors.Wrap(err)
	}()
	r = &vpn{
		subnet:      subnet,
		writerMap:   make(map[string]io.Writer),
		loggerError: &errorLogger{},
	}

	for _, optI := range opts {
		switch opt := optI.(type) {
		case optSetLoggerDump:
			r.loggerDump = opt.logger
		}
	}

	r.ifDump(func(log Logger) {
		log.Printf("creating network interface")
	})
	r.tapIface, err = water.New(water.Config{
		DeviceType: water.TAP,
	})
	r.ifDump(func(log Logger) {
		log.Printf("created network interface: %v", r.tapIface.Name())
	})
	if err != nil {
		return
	}
	r.ifDump(func(log Logger) {
		log.Printf("creating network link")
	})
	if r.tapLink, err = tenus.NewLinkFrom(r.tapIface.Name()); err != nil {
		return
	}
	r.ifDump(func(log Logger) {
		log.Printf("UP-ing network link")
	})
	if err = r.tapLink.SetLinkUp(); err != nil {
		return
	}
	r.ifDump(func(log Logger) {
		log.Printf("TAP-device is ready: %v", r.tapLink.NetInterface())
	})
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

func (vpn *vpn) setNetwork(newNetwork *network.Network) {
	vpn.LockDo(func() {
		oldNetwork := vpn.GetNetwork()
		if oldNetwork != nil {
			oldNetwork.RemoveHooker(vpn)
		}

		vpn.network.Store(newNetwork)

		newNetwork.AddHooker(vpn)
		newNetwork.SetServiceHandler(network.ServiceID_vpn, vpn)
	})
}

var (
	framebufPool = sync.Pool{
		New: func() interface{} {
			buf := make(ethernet.Frame, TAPFrameMaxSize)
			return &buf
		},
	}
)

func (vpn *vpn) Handle(authorID uint32, payload []byte) error {
	vpn.ifDump(func(log Logger) {
		log.Printf("sending to the TAP-device: %v", payload)
	})
	n, err := vpn.tapIface.Write(payload)
	if n != len(payload) && err == nil {
		err = ErrPartialWrite.Wrap(authorID, n, payload)
	}
	if err != nil {
		return errors.Wrap(err)
	}

	return nil
}

func (vpn *vpn) GetNetwork() *network.Network {
	net := vpn.network.Load()
	if net == nil {
		return nil
	}
	return net.(*network.Network)
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
		vpn.ifDump(func(log Logger) {
			log.Printf("started the TAP-reader")
		})
		for vpn.GetNetwork() != nil {
			n, err := vpn.tapIface.Read([]byte(framebuf)) // TODO: check if this request will be unblocked on vpn.tapIface.Close()
			readChan <- readChanMsg{
				n:   n,
				err: err,
			}
		}
		vpn.ifDump(func(log Logger) {
			log.Printf("stopped the TAP-reader")
		})
	}()
	for vpn.GetNetwork() != nil {
		var msg readChanMsg
		select {
		case <-vpn.closeChan:
			return
		case msg = <-readChan:
		}
		if msg.err != nil {
			vpn.loggerError.Printf("Unable to read from %s: %s", vpn.tapIface.Name(), msg.err)
			time.Sleep(time.Second)
		}
		frame := framebuf[:msg.n]

		dstMAC := macSlice(frame.Destination())

		isBroadcastDst := false
		isHomenetDst := dstMAC.IsHomenet()
		if !isHomenetDst {
			isBroadcastDst = dstMAC.IsBroadcast()
		}

		vpn.ifDump(func(log Logger) {
			log.Printf("received a frame for %v on the TAP-device: isHomenetDst: %v, isBroadcastDst: %v, length: %v", dstMAC.String(), isHomenetDst, isBroadcastDst, msg.n)
		})

		if !isHomenetDst && !isBroadcastDst {
			continue
		}

		if isHomenetDst {
			logIfError(vpn.SendToPeerByIntAlias(dstMAC.GetPeerIntAlias(), frame))
			continue
		}

		if isBroadcastDst {
			vpn.ForeachPeer(func(peer *models.PeerT) bool {
				logIfError(vpn.SendToPeer(peer, frame))
				return true
			})
			continue
		}

		panic("It should never reach this line of the code")
	}
}

func (vpn *vpn) ifDump(fn func(Logger)) {
	if vpn.loggerDump == nil {
		return
	}
	fn(vpn.loggerDump)
}

func (vpn *vpn) SendToPeer(peer *models.PeerT, frame ethernet.Frame) error {
	vpn.ifDump(func(log Logger) {
		log.Printf(`>>>	Peer: %v %v
	Dst: %s
	Src: %s
	Ethertype: % x
	Payload: % x`+"\n",
			peer.GetIntAlias(),
			peer.GetID(),
			frame.Destination(),
			frame.Source(),
			frame.Ethertype(),
			frame.Payload(),
		)
	})

	writer := vpn.writerMap[peer.GetID()]
	if writer == nil {
		writer = vpn.GetNetwork().GetPipeTo(peer, network.ServiceID_vpn)
		if writer == nil {
			vpn.ifDump(func(log Logger) {
				log.Printf("there's no path to peer %v, yet :(", peer.GetID())
			})
			return ErrNoPath
		}
		vpn.writerMap[peer.GetID()] = writer
	}

	_, err := writer.Write(frame)
	return err
}

func (vpn *vpn) SendToPeerByIntAlias(peerIntAlias uint32, frame []byte) error {
	peer := vpn.GetNetwork().GetPeerByIntAlias(peerIntAlias)
	if peer == nil {
		return errors.Wrap(ErrPeerNotFound, "integer alias", peerIntAlias)
	}
	return errors.Wrap(vpn.SendToPeer(peer, frame))
}

func (vpn *vpn) ForeachPeer(fn func(peer *models.PeerT) bool) {
	homenet := vpn.GetNetwork()
	myPeerID := homenet.GetPeerID()
	peers := homenet.GetPeers()
	for _, peer := range peers {
		if peer.GetID() == myPeerID {
			continue
		}
		if !fn(peer) {
			break
		}
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
