package vpn

import (
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/go-homedir"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"

	"github.com/xaionaro-go/homenet-server/models"

	"github.com/xaionaro-go/homenet-peer/cypher"
	"github.com/xaionaro-go/homenet-peer/helpers"
)

type vpn struct {
	peerID    string
	closeChan chan struct{}
	tapIface  *water.Interface
	cypher    *cypher.CypherT
}

func New() (*vpn, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	cypherInstance, err := cypher.New(filepath.Join(homeDir, ".homenet"))
	if err != nil {
		return nil, err
	}
	r := &vpn{
		cypher: cypherInstance,
	}

	r.peerID = helpers.ToHEX(r.cypher.GetKeys().Public)

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

func (vpn *vpn) GetPeerID() string {
	return vpn.peerID
}
