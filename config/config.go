package config

import (
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caarlos0/env"
)

var configInstance atomic.Value

type config struct {
	NetworkID                 string        `env:"HOMENET_PEER_NETWORK_ID" envDefault:"readfile:${HOME}/.homenet/network_id"`
	PasswordFile              string        `env:"HOMENET_PEER_PASSWORD_FILE" envDefault:"${HOME}/.homenet/password"`
	PeersFile                 string        `env:"HOMENET_PEERS_FILE" envDefault:"${HOME}/.homenet/peers.json"`
	DHTDataFile               string        `env:"HOMENET_DHT_DATA_FILE" envDefault:"${HOME}/.homenet/dht_data.json"`
	DHTPeersFile              string        `env:"HOMENET_DHT_PEERS_FILE" envDefault:"${HOME}/.homenet/dht_peers.json"`
	ArbitrURL                 string        `env:"HOMENET_ARBITR_URL" envDefault:"https://homenet.dx.center/"`
	NetworkSubnet             string        `env:"HOMENET_NETWORK_SUBNET" envDefault:"10.68.0.0/16"`
	NetworkUpdateInterval     time.Duration `env:"HOMENET_NETWORK_UPDATE_INTERVAL" envDefault:"3600s"`
	DumpAPICommunications     bool          `env:"HOMENET_NETWORK_DUMP_API"`
	DumpVPNCommunications     bool          `env:"HOMENET_NETWORK_DUMP_VPN"`
	DumpNetworkCommunications bool          `env:"HOMENET_NETWORK_DUMP_MESH"`
	DumpConfiguration         bool          `env:"HOMENET_DUMP_CONFIG"`
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
	cfg.NetworkID = strings.Replace(cfg.NetworkID, `${HOME}`, homedir, -1)
	cfg.PasswordFile = strings.Replace(cfg.PasswordFile, `${HOME}`, homedir, -1)
	cfg.PeersFile = strings.Replace(cfg.PeersFile, `${HOME}`, homedir, -1)
	cfg.DHTDataFile = strings.Replace(cfg.DHTDataFile, `${HOME}`, homedir, -1)
	cfg.DHTPeersFile = strings.Replace(cfg.DHTPeersFile, `${HOME}`, homedir, -1)
	configInstance.Store(cfg)
}

func Get() config {
	return *configInstance.Load().(*config)
}
