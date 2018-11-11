package main

import (
	"net/http"
	"os"
	"time"

	"github.com/Sirupsen/logrus"

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
		logrus.Fatalf("%s", err.Error())
	}
}

func main() {
	homenet, err := vpn.New()
	fatalIf(err)

	homenetServer := api.New(defaultArbitr, string(helpers.Hash([]byte(os.Getenv("HOMENET_PEER_PASSWORDHASH")))))
	status, net, err := homenetServer.GetNet(os.Getenv("HOMENET_PEER_NETWORK_ID"))
	if status == http.StatusNotFound {
		status, net, err = homenetServer.RegisterNet(os.Getenv("HOMENET_PEER_NETWORK_ID"))
	}
	fatalIf(err)

	_, peers, err := homenetServer.GetPeers(net.GetID())
	fatalIf(err)
	fatalIf(homenet.UpdatePeers(peers))

	ticker := time.NewTicker(networkUpdateInterval)
	for {
		<-ticker.C
		_, peers, err := homenetServer.GetPeers(net.GetID())
		if err != nil {
			logrus.Errorf("homenetServer.GetPeers(%s): %s", net.GetID(), err.Error())
		}
		err = homenet.UpdatePeers(peers)
		if err != nil {
			logrus.Errorf("vpn.UpdatePeers(): %s", err.Error())
		}
	}
}
