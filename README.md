# Intro

The parent project is [mynet](https://github.com/my-network/mynet). This module is responsible for creating a VPN
through all required devices. It could be used as a separate solution (on a server, for example), but it was
supposed to use [mynet](https://github.com/my-network/mynet) on desktops

# Architecture

We use:
* [IPFS](https://ipfs.io/). It's used as:
  - Node discovery (using their DHT).
  - Fallback connector (when it's impossible to connect nodes directly).
  - STUN-replacement (a helper tools to pass-trough a NAT).
* [WireGuard](https://www.wireguard.com/). It's used as the VPN implementation. When OS doesn't support WireGuard we
  detect it and use an userspace implementation.

# NAT traversal

Used techniques:
 * [UPnP IGD](https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol)
 * [UDP hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching)
 * Relaying

# Quick start

Just run on *all* your nodes (the sample commands):
```sh
# install
go get github.com/my-network/ipvpn/cmd/ipvpnd
sudo mkdir /var/run/wireguard
sudo chown $UID /var/run/wireguard
sudo setcap cap_net_raw,cap_net_admin+ep `go env GOPATH`/bin/ipvpnd

# configure
mkdir -p "$HOME/.ipvpn"
echo "my_unique_network_name_here" > "$HOME/ipvpn/network_id.txt"
echo "my_password_here" > "$HOME/.ipvpn/password_new.txt"

# run
`go env GOPATH`/bin/ipvpnd

# in other terminal, check:
ip a show dev ipvpn_direct
ip a show dev ipvpn_tunnel
ping -c 5 10.197.202.1
ping -c 5 10.197.203.1
```

* `my_unique_network_here` should be replaced by a name of you virtual private network
* `my_password_here` should be replaced by some secret string

That's it. If `my_unique_network_here` and `my_password_here` will match through all of our nodes then they will build an overlay
network automatically. 

# Similar projects
* [https://github.com/Gawen/WireHub](https://github.com/Gawen/WireHub)