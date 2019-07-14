package main

import (
	"github.com/my-network/ipvpn/ipvpn"
	"github.com/sirupsen/logrus"
)

func fatalIfError(err error) {
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}
}

func main() {
	ipvpnInstance, err := ipvpn.NewIPVPN()
	fatalIfError(err)
	select {}
	_ = ipvpnInstance.Close()
}
