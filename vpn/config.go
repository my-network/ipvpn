package vpn

import (
	"encoding/json"
)

type PeerConfig struct {
	DirectWGPort     uint16
	SimpleTunnelPort uint16
}

type Config struct {
	IntAlias           IntAlias
	DirectWGPort       uint16
	SimpleTunnelPort   uint16
	IPFSWGPort         uint16
	SimpleTunnelWGPort uint16
	Peers              map[string]PeerConfig
}

func (cfg Config) Copy() *Config {
	return &cfg
}

func (cfg *Config) Unmarshal(b []byte) error {
	return json.Unmarshal(b, cfg)
}

func (cfg *Config) Marshal() ([]byte, error) {
	return json.Marshal(cfg)
}
