all: install

install:
	CGO_ENABLED=0 go1.13beta1 get ./cmd/ipvpnd/ && sudo setcap cap_net_raw,cap_net_admin+ep `go env GOPATH`/bin/ipvpnd

run:
	~/go/bin/ipvpnd
