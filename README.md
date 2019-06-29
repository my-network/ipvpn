On all your nodes:
```sh
# install
go get github.com/xaionaro-go/ipvpn/cmd/ipvpnd
sudo mkdir /var/run/wireguard
sudo chown $UID /var/run/wireguard
sudo setcap cap_net_raw,cap_net_admin+ep `go env GOPATH`/bin/ipvpnd

# configure
mkdir -p "$HOME/.ipvpn"
echo "my_unique_network_name_here" > "$HOME/ipvpn/network_id.txt"
echo "my_password_here" > "$HOME/.ipvpn/password_new.txt""

# run
`go env GOPATH`/bin/ipvpnd

# in other terminal, check:
ip a show dev ipvpn
ping 10.68.0.1
```

* `my_unique_network_here` should be replaced by a name of you virtual private network
* `my_password_here` should be replaced by some secret string
