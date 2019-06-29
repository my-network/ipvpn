```sh
# install
go get github.com/xaionaro-go/ipvpn/cmd/ipvpnd

# configure
mkdir -p "$HOME/.ipvpn"
apg -x 30 -n 1 > "$HOME/.ipvpn/password_new.txt""
echo "my_unique_network_name_here" > "$HOME/ipvpn/network_id.txt"

# run
sudo setcap cap_net_raw,cap_net_admin+ep `go env GOPATH`/bin/ipvpnd
`go env GOPATH`/bin/ipvpnd
```
