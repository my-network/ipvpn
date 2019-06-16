package main

import (
	"fmt"
	"github.com/xaionaro-go/homenet-peer/connector"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/denisbrodbeck/machineid"

	"github.com/xaionaro-go/homenet-peer/config"
	"github.com/xaionaro-go/homenet-peer/helpers"
	"github.com/xaionaro-go/homenet-peer/negotiator"
	"github.com/xaionaro-go/homenet-peer/network"
	"github.com/xaionaro-go/homenet-peer/vpn"
	"github.com/xaionaro-go/homenet-server/api"
)

const (
	MachineIDLength = 8
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
	logrus.SetLevel(logrus.DebugLevel)

	if config.Get().DumpConfiguration {
		logrus.Debugf("Configuration == %v", config.Get())
	}

	var apiOptions api.Options
	if config.Get().DumpAPICommunications {
		apiOptions = append(apiOptions, api.OptSetLoggerDebug(&debugLogger{}))
	}

	networkID := config.Get().NetworkID
	passwordHashHash := string(helpers.Hash([]byte(config.Get().PasswordHash)))
	homenetServer := api.New(config.Get().ArbitrURL, passwordHashHash, apiOptions...)
	status, netInfo, err := homenetServer.GetNet(networkID)
	fatalIf(err)
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		status, netInfo, err = homenetServer.RegisterNet(networkID)
	default:
		panic(fmt.Errorf("received an unexpected HTTP status code from the arbitr: %v", status))
	}

	var vpnOptions vpn.Options
	if config.Get().DumpVPNCommunications {
		vpnOptions = append(vpnOptions, vpn.OptSetLoggerDump(&debugLogger{}))
	}

	_, subnet, err := net.ParseCIDR(config.Get().NetworkSubnet)
	fatalIf(err)

	homenet, err := network.New(nil, &logger{})
	fatalIf(err)

	connectorInstance := connector.New(negotiator.New(config.Get().NetworkUpdateInterval, homenetServer, networkID, homenet))

	homenet.SetConnector(connectorInstance)

	_, err = vpn.New(*subnet, homenet)
	fatalIf(err)

	hostname, _ := os.Hostname()
	machineID, _ := machineid.ProtectedID("homenet-peer")
	if len(machineID) > MachineIDLength {
		machineID = machineID[:MachineIDLength]
	}
	peerName := hostname + "_" + machineID
	if peerName == "_" {
		peerName = ""
	}

	_, _, err = homenetServer.RegisterPeer(netInfo.GetID(), homenet.GetPeerID(), peerName)
	fatalIf(err)

	_, peers, err := homenetServer.GetPeers(netInfo.GetID())
	fatalIf(err)
	fatalIf(homenet.UpdatePeers(peers))

	ticker := time.NewTicker(config.Get().NetworkUpdateInterval)
	for {
		<-ticker.C
		_, _, err = homenetServer.RegisterPeer(netInfo.GetID(), homenet.GetPeerID(), peerName)
		if err != nil {
			logrus.Errorf("homenetServer.RegisterPeer(%s, %s): %s", netInfo.GetID(), homenet.GetPeerID(), err.Error())
		}
		_, peers, err := homenetServer.GetPeers(netInfo.GetID())
		if err != nil {
			logrus.Errorf("homenetServer.GetPeers(%s): %s", netInfo.GetID(), err.Error())
		}
		err = homenet.UpdatePeers(peers)
		if err != nil {
			logrus.Errorf("homenet.UpdatePeers(): %s", err.Error())
		}
	}
}
