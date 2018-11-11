package vpn

import (
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"

	"github.com/xaionaro-go/homenet-server/models"
)

type vpn struct {
	closeChan chan struct{}
	tapIface  *water.Interface
}

func New() (*vpn, error) {
	r := &vpn{}

	var err error
	r.tapIface, err = water.New(water.Config{
		DeviceType: water.TAP,
	})
	if err != nil {
		return nil, err
	}

	go r.readHandler()

	return r, nil
}

func (vpn *vpn) readHandler() {
	var frame ethernet.Frame
	for {
		frame.Resize(1500)
		n, err := vpn.tapIface.Read([]byte(frame))
		if err != nil {
			logrus.Errorf("Unable to read from %s: %s", vpn.tapIface.Name(), err)
			time.Sleep(time.Second)
		}
		frame = frame[:n]
		logrus.Printf("Dst: %s\n", frame.Destination())
		logrus.Printf("Src: %s\n", frame.Source())
		logrus.Printf("Ethertype: % x\n", frame.Ethertype())
		logrus.Printf("Payload: % x\n", frame.Payload())
	}
}

func (vpn *vpn) Close() {
	vpn.closeChan <- struct{}{}
	vpn.tapIface.Close()
}

func (vpn *vpn) UpdatePeers(peers models.Peers) error {
	return nil
}
