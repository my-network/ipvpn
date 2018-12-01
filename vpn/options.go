package vpn

type Option interface {
	HomenetVPNOptionMethod()
}
type Options []Option

type optionBase struct{}

func (opt optionBase) HomenetVPNOptionMethod() {
}

type optSetLoggerDump struct {
	optionBase

	logger Logger
}

func OptSetLoggerDump(logger Logger) optSetLoggerDump {
	return optSetLoggerDump{
		logger: logger,
	}
}
