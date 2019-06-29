package vpn

import (
	"net"
)

type MessageConfig struct {
	RoutedNetworks []net.IPNet
}
