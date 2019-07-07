package helpers

type Logger interface {
	Error(...interface{})
	Infof(string, ...interface{})
	Debugf(string, ...interface{})
}
