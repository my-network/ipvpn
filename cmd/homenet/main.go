package main

import (
	"fmt"
	"github.com/xaionaro-go/homenet-server/errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/denisbrodbeck/machineid"

	"github.com/xaionaro-go/homenet-peer/config"
	"github.com/xaionaro-go/homenet-peer/connector"
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
		logrus.Fatalf("%s", err.Error())
	}
}

func errorIf(err error) {
	if err != nil {
		logrus.Error(err)
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

	if strings.HasPrefix(networkID, `readfile:`) {
		networkIDBytes, err := ioutil.ReadFile(networkID[len(`readfile:`)-1:])
		fatalIf(err)
		networkID = string(networkIDBytes)
	}

	passwordFile := config.Get().PasswordFile
	password, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		panic(fmt.Errorf(`cannot read the password file "%v"`, passwordFile))
	}

	passwordHashHash := string(helpers.Hash([]byte(strings.Trim(string(password), " \t\n\r"))))
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

	netLogger := &logger{config.Get().DumpNetworkCommunications}

	homenet, err := network.New(nil, netLogger)
	fatalIf(err)

	connectorInstance := connector.New(negotiator.New(config.Get().NetworkUpdateInterval, homenetServer, networkID, homenet, netLogger), netLogger)

	homenet.SetConnector(connectorInstance)

	_, err = vpn.New(*subnet, homenet, vpnOptions...)
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

	peers, err := network.ParsePeersFromFile(config.Get().PeersFile)
	if err == nil {
		fatalIf(homenet.UpdatePeers(peers))
	}

	homenet.AddHooker(&savePeersHandler{
		homenet:       homenet,
		peersFilePath: config.Get().PeersFile,
	})

	_, _, err = homenetServer.RegisterPeer(netInfo.GetID(), homenet.GetPeerID(), peerName, homenet.GetIdentity().Keys.Public)
	fatalIf(err)

	_, peers, err = homenetServer.GetPeers(netInfo.GetID())
	errorIf(errors.Wrap(err))
	if err == nil {
		errorIf(errors.Wrap(homenet.UpdatePeers(peers)))
	}

	ticker := time.NewTicker(config.Get().NetworkUpdateInterval)
	for {
		<-ticker.C
		_, _, err = homenetServer.RegisterPeer(netInfo.GetID(), homenet.GetPeerID(), peerName, homenet.GetIdentity().Keys.Public)
		errorIf(errors.Wrap(err))
		_, peers, err := homenetServer.GetPeers(netInfo.GetID())
		if err != nil {
			logrus.Errorf("homenetServer.GetPeers(%s): %s", netInfo.GetID(), err.Error())
			continue
		}
		errorIf(errors.Wrap(homenet.UpdatePeers(peers)))
		if err != nil {
			logrus.Errorf("homenet.UpdatePeers(): %s", err.Error())
		}
	}
}
