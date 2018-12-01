package vpn

import (
	"github.com/Sirupsen/logrus"
)

func fatalIf(err error) {
	if err != nil {
		logrus.Fatalf("%v", err)
	}
}
