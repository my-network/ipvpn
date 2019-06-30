package config

import (
	"encoding/json"
	"github.com/caarlos0/env"
	"os"
	"strings"
	"sync/atomic"
)

var configInstance atomic.Value

type config struct {
	DataDirectory             string `env:"IPVPN_DATADIR" envDefault:"${HOME}/.ipvpn"`
	NetworkSubnet             string `env:"IPVPN_NETWORK_SUBNET" envDefault:"10.197.202.0/23"`
	DumpVPNCommunications     bool   `env:"IPVPN_NETWORK_DUMP_VPN"`
	DumpNetworkCommunications bool   `env:"IPVPN_NETWORK_DUMP_MESH"`
	DumpConfiguration         bool   `env:"IPVPN_DUMP_CONFIG"`
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
	homedir, _ := os.UserHomeDir()
	cfg.DataDirectory = strings.Replace(cfg.DataDirectory, `${HOME}`, homedir, -1)
	configInstance.Store(cfg)
}

func Get() config {
	return *configInstance.Load().(*config)
}
