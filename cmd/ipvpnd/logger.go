package main

import (
	"github.com/Sirupsen/logrus"
)

type logger struct {
	enableDebug bool
}

func (l *logger) Error(args ...interface{}) {
	logrus.Error(args...)
}

func (l *logger) Infof(fm string, args ...interface{}) {
	logrus.Infof(fm, args...)
}

func (l *logger) Debugf(fm string, args ...interface{}) {
	if !l.enableDebug {
		return
	}
	logrus.Debugf(fm, args...)
}
