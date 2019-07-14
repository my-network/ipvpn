package router

import (
	"github.com/my-network/ipvpn/vpn"
)

var _ vpn.UpperHandler = (*Router)(nil)
