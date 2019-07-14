module github.com/my-network/ipvpn

go 1.13

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/caarlos0/env v3.5.0+incompatible
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/ipfs/go-cid v0.0.2
	github.com/ipfs/go-ipfs v0.4.22-0.20190703233353-70e499afbc16
	github.com/ipfs/go-ipfs-config v0.0.6
	github.com/libp2p/go-libp2p v0.2.0
	github.com/libp2p/go-libp2p-core v0.0.6
	github.com/libp2p/go-libp2p-kbucket v0.2.0
	github.com/libp2p/go-libp2p-peer v0.2.0
	github.com/multiformats/go-multiaddr v0.0.4
	github.com/multiformats/go-multihash v0.0.6
	github.com/my-network/routewrapper v0.0.0-20190714184510-90e66eda123f
	github.com/my-network/wgcreate v0.0.0-20190707165004-31e33f68f780
	github.com/sirupsen/logrus v1.4.2
	github.com/sparrc/go-ping v0.0.0-20190613174326-4e5b6552494c
	github.com/stretchr/testify v1.3.0
	github.com/xaionaro-go/atomicmap v0.0.0-20190707161005-2e6f4aeaa450
	github.com/xaionaro-go/errors v0.0.0-20190618051035-77224f41226e
	github.com/xaionaro-go/pinentry v0.0.0-20190317135045-959eecdd5c53
	github.com/xaionaro-go/spinlock v0.0.0-20190309154744-55278e21e817 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/sys v0.0.0-20190626221950-04f50cda93cb
	golang.org/x/xerrors v0.0.0-20190528162220-0421b64034aa
	golang.zx2c4.com/wireguard v0.0.20190517
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20190629151639-28f4e240be2d
)

replace github.com/libp2p/go-libp2p-quic-transport => github.com/my-network/go-libp2p-quic-transport v0.1.2-0.20190702052731-897c7bdaec45
