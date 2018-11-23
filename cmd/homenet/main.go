package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/denisbrodbeck/machineid"

	"github.com/xaionaro-go/homenet-peer/config"
	"github.com/xaionaro-go/homenet-peer/helpers"
	"github.com/xaionaro-go/homenet-peer/vpn"
	"github.com/xaionaro-go/homenet-server/api"
)

func fatalIf(err error) {
	if err != nil {
		logrus.Panicf("%s", err.Error())
	}
}

type debugLogger struct{}

func (l *debugLogger) Printf(fmt string, args ...interface{}) {
	logrus.Debugf(fmt, args...)
}

func (l *debugLogger) Print(args ...interface{}) {
	logrus.Debug(args...)
}

func main() {
	homenet, err := vpn.New()
	fatalIf(err)

	var apiOptions api.Options
	if config.Get().DumpAPICommunications {
		logrus.SetLevel(logrus.DebugLevel)
		apiOptions = append(apiOptions, api.OptSetLoggerDebug(&debugLogger{}))
	}

	networkID := config.Get().NetworkID
	passwordHashHash := string(helpers.Hash([]byte(config.Get().PasswordHash)))
	homenetServer := api.New(config.Get().ArbitrURL, passwordHashHash, apiOptions...)
	status, net, err := homenetServer.GetNet(networkID)
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		status, net, err = homenetServer.RegisterNet(networkID)
	default:
		panic(fmt.Errorf("received an unexpected HTTP status code from the arbitr: %v", status))
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

	ticker := time.NewTicker(config.Get().NetworkUpdateInterval)
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
