package config

import (
	"sync/atomic"
	"time"

	"github.com/caarlos0/env"
)

var configInstance atomic.Value

type config struct {
	NetworkID             string        `env:"HOMENET_PEER_NETWORK_ID"`
	PasswordHash          string        `env:"HOMENET_PEER_PASSWORDHASH"`
	ArbitrURL             string        `env:"HOMENET_ARBITR_URL" envDefault:"https://homenet.dx.center/"`
	NetworkUpdateInterval time.Duration `env:"HOMENET_NETWORK_UPDATE_INTERVAL" envDefault:"10s"`
	DumpAPICommunications bool          `env:"HOMENET_NETWORK_DUMP_API"`
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

func init() {
	cfg := &config{}
	panicIf(env.Parse(cfg))
	configInstance.Store(cfg)
}

func Get() config {
	return *configInstance.Load().(*config)
}
