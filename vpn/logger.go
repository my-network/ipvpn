package vpn

import (
	"io"
)

type Logger interface {
	Error(...interface{})
	Infof(string, ...interface{})
	Debugf(string, ...interface{})

	GetDebugWriter() io.Writer
	GetInfoWriter() io.Writer
	GetErrorWriter() io.Writer
}
