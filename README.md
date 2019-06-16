```sh
# install
go get github.com/xaionaro-go/homenet-peer/cmd/homenet
go install github.com/xaionaro-go/homenet-peer/cmd/homenet

# configure
apg -x 30 -n 1 > "$HOME/.homenet-password"
export HOMENET_PEER_NETWORK_ID=my_unique_network_name_here
export HOMENET_PEER_PASSWORD_FILE="$HOME/.homenet-password"
export HOMENET_NETWORK_SUBNET=192.168.204.0/24

# run
sudo setcap cap_net_raw,cap_net_admin+ep `go env GOPATH`/bin/homenet
`go env GOPATH`/bin/homenet
```
