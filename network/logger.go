package network

import (
	"github.com/Sirupsen/logrus"
)

type Logger interface {
	Printf(fmt string, args ...interface{})
}

type errorLogger struct{}

func (l *errorLogger) Printf(fmt string, args ...interface{}) {
	logrus.Errorf(fmt, args...)
}
