package main

import (
	"net/http"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/denisbrodbeck/machineid"

	"github.com/xaionaro-go/homenet-peer/helpers"
	"github.com/xaionaro-go/homenet-peer/vpn"
	"github.com/xaionaro-go/homenet-server/api"
)

const (
	defaultArbitr         = "https://homenet.dx.center/"
	networkUpdateInterval = time.Second * 10
)

func fatalIf(err error) {
	if err != nil {
		logrus.Panicf("%s", err.Error())
	}
}

func main() {
	networkID := os.Getenv("HOMENET_PEER_NETWORK_ID")

	homenet, err := vpn.New()
	fatalIf(err)

	arbitr := os.Getenv("HOMENET_ARBITR_URL")
	if arbitr == "" {
		arbitr = defaultArbitr
	}

	homenetServer := api.New(arbitr, string(helpers.Hash([]byte(os.Getenv("HOMENET_PEER_PASSWORDHASH")))))
	status, net, err := homenetServer.GetNet(networkID)
	if status == http.StatusNotFound {
		status, net, err = homenetServer.RegisterNet(os.Getenv("HOMENET_PEER_NETWORK_ID"))
	}
	fatalIf(err)

	hostname, _ := os.Hostname()
	machineID, _ := machineid.ProtectedID("homenet-peer")
	if len(machineID) > 8 {
		machineID = machineID[:8]
	}
	peerName := hostname + "_" + machineID
	if peerName == "_" {
		peerName = ""
	}

	_, _, err = homenetServer.RegisterPeer(net.GetID(), homenet.GetPeerID(), peerName)
	fatalIf(err)

	_, peers, err := homenetServer.GetPeers(net.GetID())
	fatalIf(err)
	fatalIf(homenet.UpdatePeers(peers))

	ticker := time.NewTicker(networkUpdateInterval)
	for {
		<-ticker.C
		_, _, err = homenetServer.RegisterPeer(net.GetID(), homenet.GetPeerID(), peerName)
		if err != nil {
			logrus.Errorf("homenetServer.RegisterPeer(%s, %s): %s", net.GetID(), homenet.GetPeerID(), err.Error())
		}
		_, peers, err := homenetServer.GetPeers(net.GetID())
		if err != nil {
			logrus.Errorf("homenetServer.GetPeers(%s): %s", net.GetID(), err.Error())
		}
		err = homenet.UpdatePeers(peers)
		if err != nil {
			logrus.Errorf("homenet.UpdatePeers(): %s", err.Error())
		}
	}
}
