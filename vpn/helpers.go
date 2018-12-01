package vpn

import (
	"github.com/Sirupsen/logrus"
)

func fatalIf(err error) {
	if err == nil {
		return
	}
	logrus.Fatalf("%v", err)
}
func logIfError(err error) {
	if err == nil {
		return
	}
	logrus.Errorf("%v", err)
}
