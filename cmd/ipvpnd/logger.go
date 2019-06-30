package main

import (
	"github.com/sirupsen/logrus"
	"io"
)

type logger struct {
	prefix      string
	enableInfo  bool
	enableDebug bool
}

func (l *logger) Error(args ...interface{}) {
	logrus.Error(append([]interface{}{l.prefix}, args...)...)
}

func (l *logger) Infof(fm string, args ...interface{}) {
	if !l.enableInfo {
		return
	}
	logrus.Infof(l.prefix+" "+fm, args...)
}

func (l *logger) Debugf(fm string, args ...interface{}) {
	if !l.enableDebug {
		return
	}
	logrus.Debugf(l.prefix+" "+fm, args...)
}

type loggerDebugWriter struct {
	*logger
}

func (l *loggerDebugWriter) Write(b []byte) (int, error) {
	l.Debugf("%v", string(b))
	return len(b), nil
}

func (l *logger) GetDebugWriter() io.Writer {
	return &loggerDebugWriter{l}
}

type loggerInfoWriter struct {
	*logger
}

func (l *loggerInfoWriter) Write(b []byte) (int, error) {
	l.Infof("%v", string(b))
	return len(b), nil
}

func (l *logger) GetInfoWriter() io.Writer {
	return &loggerInfoWriter{l}
}

type loggerErrorWriter struct {
	*logger
}

func (l *loggerErrorWriter) Write(b []byte) (int, error) {
	l.Error((string)(b))
	return len(b), nil
}

func (l *logger) GetErrorWriter() io.Writer {
	return &loggerErrorWriter{l}
}
