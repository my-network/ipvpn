module github.com/my-network/ipvpn

go 1.13

require (
	github.com/OneOfOne/xxhash v1.2.5 // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/caarlos0/env v3.5.0+incompatible
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/ipfs/go-cid v0.0.3
	github.com/ipfs/go-ipfs v0.4.22-0.20190904220133-06153e088e2b
	github.com/ipfs/go-ipfs-config v0.0.11
	github.com/libp2p/go-libp2p v0.3.1
	github.com/libp2p/go-libp2p-core v0.2.2
	github.com/libp2p/go-libp2p-kbucket v0.2.1
	github.com/multiformats/go-multiaddr v0.0.4
	github.com/multiformats/go-multihash v0.0.7
	github.com/my-network/routewrapper v0.0.0-20190720192949-2e94b90580e3
	github.com/my-network/wgcreate v0.0.0-20190707165004-31e33f68f780
	github.com/sirupsen/logrus v1.4.2
	github.com/sparrc/go-ping v0.0.0-20190613174326-4e5b6552494c
	github.com/xaionaro-go/atomicmap v0.0.0-20190720091258-77e7f2aaf663
	github.com/xaionaro-go/errors v0.0.0-20190618051035-77224f41226e
	github.com/xaionaro-go/pinentry v0.0.0-20190817122727-387561e90903
	github.com/xaionaro-go/spinlock v0.0.0-20190309154744-55278e21e817 // indirect
	golang.org/x/crypto v0.0.0-20190829043050-9756ffdc2472
	golang.org/x/sys v0.0.0-20190904154756-749cb33beabd
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
	golang.zx2c4.com/wireguard v0.0.20190806-0.20190831134842-7937840f9631
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20190904205523-599d41c32142
)

replace github.com/go-critic/go-critic => github.com/go-critic/go-critic v0.3.4

replace github.com/golangci/ineffassign => github.com/golangci/ineffassign v0.0.0-20180808204949-2ee8f2867dde

replace github.com/libp2p/go-libp2p-quic-transport => github.com/my-network/go-libp2p-quic-transport v0.1.2-0.20190702052731-897c7bdaec45
