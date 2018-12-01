package config

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/caarlos0/env"
)

var configInstance atomic.Value

type config struct {
	NetworkID             string        `env:"HOMENET_PEER_NETWORK_ID"`
	PasswordHash          string        `env:"HOMENET_PEER_PASSWORDHASH"`
	ArbitrURL             string        `env:"HOMENET_ARBITR_URL" envDefault:"https://homenet.dx.center/"`
	NetworkSubnet         string        `env:"HOMENET_NETWORK_SUBNET" envDefault:"10.68.88.0/24"`
	NetworkUpdateInterval time.Duration `env:"HOMENET_NETWORK_UPDATE_INTERVAL" envDefault:"10s"`
	DumpAPICommunications bool          `env:"HOMENET_NETWORK_DUMP_API"`
	DumpConfiguration     bool          `env:"HOMENET_DUMP_CONFIG"`
}

func (cfg config) String() string {
	json, err := json.MarshalIndent(cfg, "", "\t")
	panicIf(err)
	return string(json)
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
