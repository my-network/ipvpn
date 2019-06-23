package vpn

import (
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
)

type IntAlias struct {
	PeerID         peer.ID
	Value          uint64
	MaxNetworkSize uint64
	Timestamp      time.Time     `json:",omitempty"`
	Since          time.Duration `json:",omitempty"`
}

func (alias IntAlias) Copy() *IntAlias {
	return &alias
}

func (alias *IntAlias) Unmarshal(b []byte) error {
	return json.Unmarshal(b, alias)
}

func (alias *IntAlias) Marshal() ([]byte, error) {
	return json.Marshal(alias)
}

type IntAliases []*IntAlias

func (aliases *IntAliases) Unmarshal(b []byte) error {
	return json.Unmarshal(b, aliases)
}

func (aliases *IntAliases) Marshal() ([]byte, error) {
	return json.Marshal(aliases)
}
