package network

import (
	"bytes"
	"context"
	"crypto/sha512"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ipfs/go-cid"
	ipfsConfig "github.com/ipfs/go-ipfs-config"
	"github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/plugin/loader"
	"github.com/ipfs/go-ipfs/repo"
	"github.com/ipfs/go-ipfs/repo/fsrepo"
	p2pcore "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	p2pprotocol "github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multihash"
	"github.com/xaionaro-go/errors"
)

const (
	p2pProtocolID = p2pprotocol.ID(`/p2p/github.com/xaionaro-go/ipvpn`)
	ipvpnMagic    = "\000\314\326This is an InterPlanetary Virtual Private Network node"
)

type Network struct {
	logger                Logger
	networkName           string
	publicSharedKeyword   []byte
	privateSharedKeyword  []byte
	ipfsNode              *core.IpfsNode
	ipfsContext           context.Context
	ipfsContextCancelFunc func()
	streams               sync.Map
	streamHandlers        []StreamHandler
}

type Stream = p2pcore.Stream
type AddrInfo = peer.AddrInfo

// generatePublicSharedKeyword generates a keyword, shared through all nodes of the network "networkName"
func generatePublicSharedKeyword(networkName string, psk []byte) []byte {
	hasher := sha512.New()
	pskBasedSum := hasher.Sum(append(psk, []byte(networkName)...))

	// We want to keyword be generated correctly only in case of correct networkName _AND_ psk.
	// However we don't want to compromise psk and we don't trust any hashing algorithm, so
	// we're using only a half of a hash of the "psk" to generate the keyword.
	var buf bytes.Buffer
	buf.Write(pskBasedSum[:len(pskBasedSum)/2])
	buf.WriteString(networkName)
	buf.WriteString(ipvpnMagic)

	return hasher.Sum(buf.Bytes())
}

func generatePrivateSharedKeyword(networkName string, psk []byte) []byte {
	hasher := sha512.New()
	pskBasedSum := hasher.Sum(append(psk, []byte(networkName)...))

	var buf bytes.Buffer
	buf.Write(pskBasedSum)
	buf.WriteString(networkName)

	return hasher.Sum(buf.Bytes())
}

func checkCacheDir(cacheDir string) (err error) {
	var stat os.FileInfo
	stat, err = os.Stat(cacheDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
		return os.MkdirAll(cacheDir, 0750)
	}

	if !stat.IsDir() {
		return errors.New(syscall.ENOTDIR, cacheDir)
	}
	if err := unix.Access(cacheDir, unix.W_OK); err != nil {
		return errors.Wrap(err, "no permission to read/write within directory", cacheDir)
	}
	return
}

func addressesConfig() ipfsConfig.Addresses {
	return ipfsConfig.Addresses{
		Swarm: []string{
			"/ip4/0.0.0.0/tcp/24001",
			"/ip4/0.0.0.0/udp/24001",
			"/ip6/::/tcp/24001",
			"/ip6/::/udp/24001",
			// Also we need ICMP :(
		},
		Announce:   []string{},
		NoAnnounce: []string{},
		API:        ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/25001"},
		Gateway:    ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/28080"},
	}
}

func initRepo(logger Logger, repoPath string) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	logger.Debugf(`generating keys`)

	privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, 521)
	if err != nil {
		return
	}

	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return
	}

	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return
	}

	identity := ipfsConfig.Identity{
		PeerID:  peerID.Pretty(),
		PrivKey: crypto.ConfigEncodeKey(privKeyBytes),
	}

	logger.Debugf(`initializing the repository`)

	bootstrapPeers, err := ipfsConfig.DefaultBootstrapPeers()
	if err != nil {
		return
	}

	err = fsrepo.Init(repoPath, &ipfsConfig.Config{
		Identity:  identity,
		Addresses: addressesConfig(),
		Bootstrap: ipfsConfig.BootstrapPeerStrings(bootstrapPeers),
		/*Mounts: ipfsConfig.Mounts{
			IPFS: "/ipfs",
			IPNS: "/ipns",
		},*/
		Datastore: ipfsConfig.DefaultDatastoreConfig(),
		Discovery: ipfsConfig.Discovery{
			MDNS: ipfsConfig.MDNS{
				Enabled:  true,
				Interval: 10,
			},
		},
		Routing: ipfsConfig.Routing{
			Type: "dht",
		},
		Ipns: ipfsConfig.Ipns{
			ResolveCacheSize: 256,
		},
		Reprovider: ipfsConfig.Reprovider{
			Interval: "12h", // just used the same value as in go-ipfs-config/init.go
			Strategy: "all",
		},
		Swarm: ipfsConfig.SwarmConfig{
			ConnMgr: ipfsConfig.ConnMgr{ // just used the same values as in go-ipfs-config/init.go
				LowWater:    ipfsConfig.DefaultConnMgrLowWater,
				HighWater:   ipfsConfig.DefaultConnMgrHighWater,
				GracePeriod: ipfsConfig.DefaultConnMgrGracePeriod.String(),
				Type:        "basic",
			},
		},
	})
	if err != nil {
		return
	}

	return
}

type VPN interface {
}

func New(networkName string, psk []byte, cacheDir string, logger Logger, streamHandlers ...StreamHandler) (mesh *Network, err error) {
	defer func() {
		if err != nil {
			mesh = nil
			err = errors.Wrap(err)
		}
	}()

	logger.Debugf(`loading IPFS plugins`)

	loader, err := loader.NewPluginLoader(``)
	if err != nil {
		return
	}
	err = loader.Inject()
	if err != nil {
		return
	}

	logger.Debugf(`checking the directory "%v"`, cacheDir)

	if err := checkCacheDir(filepath.Join(cacheDir, "ipfs")); err != nil {
		return nil, errors.Wrap(err, "invalid cache directory")
	}

	repoPath := filepath.Join(cacheDir, "ipfs")

	if !fsrepo.IsInitialized(repoPath) {
		logger.Debugf(`repository "%v" not initialized`, repoPath)

		err = initRepo(logger, repoPath)
		if err != nil {
			return
		}
	}

	logger.Debugf(`opening the repository "%v"`, repoPath)

	var ipfsRepo repo.Repo
	ipfsRepo, err = fsrepo.Open(repoPath)
	if err != nil {
		return
	}

	ctx, cancelFunc := context.WithCancel(context.Background())

	ipfsCfg := &core.BuildCfg{
		Repo:      ipfsRepo,
		Online:    true,
		Permanent: true,
		ExtraOpts: map[string]bool{
			"pubsub": true,
			"ipnsps": true,
		},
	}

	logger.Debugf(`creating an IPFS node`)

	var ipfsNode *core.IpfsNode
	ipfsNode, err = core.NewNode(ctx, ipfsCfg)
	if err != nil {
		return
	}

	mesh = &Network{
		logger:                logger,
		networkName:           networkName,
		publicSharedKeyword:   generatePublicSharedKeyword(networkName, psk),
		privateSharedKeyword:  generatePrivateSharedKeyword(networkName, psk),
		ipfsNode:              ipfsNode,
		ipfsContext:           ctx,
		ipfsContextCancelFunc: cancelFunc,
		streamHandlers:        streamHandlers,
	}

	err = mesh.start()
	if err != nil {
		_ = mesh.Close()
		return
	}

	return
}

type addrInfoWithLatencies struct {
	Latencies []time.Duration
	AddrInfo  *AddrInfo
}

func (data *addrInfoWithLatencies) Len() int           { return len(data.AddrInfo.Addrs) }
func (data *addrInfoWithLatencies) Less(i, j int) bool { return data.Latencies[i] < data.Latencies[j] }
func (data *addrInfoWithLatencies) Swap(i, j int) {
	data.Latencies[i], data.Latencies[j] = data.Latencies[j], data.Latencies[i]
	data.AddrInfo.Addrs[i], data.AddrInfo.Addrs[j] = data.AddrInfo.Addrs[j], data.AddrInfo.Addrs[i]
}

func (mesh *Network) tryConnectByOptimalPath(addrInfo *AddrInfo) {
	data := addrInfoWithLatencies{
		Latencies: make([]time.Duration, len(addrInfo.Addrs)),
		AddrInfo:  addrInfo,
	}

	// Measure latencies
	measureLatencyContext, _ := context.WithTimeout(context.Background(), time.Second)
	for idx, addr := range addrInfo.Addrs {
		data.Latencies[idx] = math.MaxInt64

		go func(idx int, addr p2pcore.Multiaddr) {
			data.Latencies[idx] = mesh.measureLatencyToMultiaddr(measureLatencyContext, addr)
		}(idx, addr)
	}
	<-measureLatencyContext.Done()

	// Prioritize paths
	sort.Sort(&data)
	mesh.logger.Debugf("prioritized paths %v %v", data.Latencies, data.AddrInfo.Addrs)

	// Closing existing connections
	for _, conn := range mesh.ipfsNode.PeerHost.Network().ConnsToPeer(addrInfo.ID) {
		if conn.RemoteMultiaddr().String() == addrInfo.Addrs[0].String() {
			mesh.logger.Debugf("we already have a connection via the optimal path")
			return
		}
		mesh.logger.Debugf("closing connection to %v via %v", addrInfo.ID, conn.RemoteMultiaddr())
		err := conn.Close()
		if err != nil {
			mesh.logger.Debugf("unable to close connection to %v: %v", addrInfo.ID, err)
		}
	}

	// Do the connection (start tries with the path with the lowest latency)
	for _, addr := range addrInfo.Addrs {
		err := mesh.ipfsNode.PeerHost.Connect(mesh.ipfsContext, AddrInfo{
			ID: addrInfo.ID,
			Addrs: []p2pcore.Multiaddr{
				addr,
			},
		})
		mesh.logger.Debugf("try connect: %v -> %v", addr, err)
		if err == nil {
			return
		}
	}
}

func (mesh *Network) connector(ipfsCid cid.Cid) {
	mesh.logger.Debugf(`initializing output streams`)

	provChan := mesh.ipfsNode.DHT.FindProvidersAsync(mesh.ipfsContext, ipfsCid, 1<<16)
	count := uint(0)
	for {
		select {
		case <-mesh.ipfsContext.Done():
			return
		case peerAddr := <-provChan:
			if peerAddr.ID == mesh.ipfsNode.PeerHost.ID() {
				mesh.logger.Debugf("my ID, skip")
				continue
			}
			if peerAddr.ID == "" {
				hours := (1 << count) - 1
				mesh.logger.Debugf("empty peer ID, sleep %v hours and restart FindProvidersAsync", hours)
				time.Sleep(time.Hour * time.Duration(hours))
				provChan = mesh.ipfsNode.DHT.FindProvidersAsync(mesh.ipfsContext, ipfsCid, 1<<16)
				count++
				continue
			}
			addrInfo, err := mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerAddr.ID)
			if err != nil {
				mesh.logger.Infof("unable to find a route to peer %v: %v", peerAddr.ID, err)
				continue
			}
			mesh.tryConnectByOptimalPath(&addrInfo)
			stream, err := mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerAddr.ID, p2pProtocolID)
			if err != nil {
				mesh.logger.Infof("unable to connect to peer %v: %v", peerAddr.ID, err)
				continue
			}
			mesh.addStream(stream, peerAddr)
		}
	}

}

func (mesh *Network) start() (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	mesh.logger.Debugf(`starting an IPFS node`)

	ipfsCid, err := cid.V1Builder{
		Codec:  cid.Raw,
		MhType: multihash.SHA2_256,
	}.Sum(mesh.publicSharedKeyword)
	if err != nil {
		return
	}

	mesh.logger.Debugf(`sending configuration stream handlers`)

	for _, streamHandler := range mesh.streamHandlers {
		streamHandler.SetID(mesh.ipfsNode.PeerHost.ID())
		streamHandler.SetPSK(mesh.privateSharedKeyword)
		privKey, err := mesh.ipfsNode.PrivateKey.Raw()
		if err != nil {
			return err
		}
		streamHandler.SetPrivateKey(privKey)
		err = streamHandler.Start()
		if err != nil {
			return err
		}
	}

	mesh.logger.Debugf(`starting to listen for the input streams handler`)

	mesh.ipfsNode.PeerHost.SetStreamHandler(p2pProtocolID, func(stream Stream) {
		mesh.addStream(stream, AddrInfo{
			ID:    stream.Conn().RemotePeer(),
			Addrs: []p2pcore.Multiaddr{stream.Conn().RemoteMultiaddr()},
		})
	})

	go mesh.connector(ipfsCid)

	mesh.logger.Infof(`My ID: %v        Calling IPFS "DHT.Provide()" on the shared key (that will be used for the node discovery), Cid: %v`, mesh.ipfsNode.PeerHost.ID(), ipfsCid)

	err = mesh.ipfsNode.DHT.Provide(mesh.ipfsContext, ipfsCid, true)
	if err != nil {
		return
	}

	mesh.logger.Debugf(`started an IPFS node`)
	return
}

func (mesh *Network) Close() (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()
	mesh.logger.Debugf(`closing an IPFS node`)
	mesh.ipfsContextCancelFunc()
	return mesh.ipfsNode.Close()
}

func (mesh *Network) sendAuthData(stream Stream) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	var buf bytes.Buffer
	buf.WriteString(string(mesh.ipfsNode.Identity))
	sum := sha512.Sum512(mesh.privateSharedKeyword)
	buf.Write(sum[:])
	sum = sha512.Sum512(buf.Bytes())
	mesh.logger.Debugf(`sending auth data to %v: %v`, stream.Conn().RemotePeer(), sum[:])
	_, err = stream.Write(sum[:])
	if err != nil {
		return
	}
	return
}

func (mesh *Network) recvAndCheckAuthData(stream Stream) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	var buf bytes.Buffer
	buf.WriteString(string(stream.Conn().RemotePeer()))
	sum := sha512.Sum512(mesh.privateSharedKeyword)
	buf.Write(sum[:])
	sum = sha512.Sum512(buf.Bytes())
	expectedAuthData := sum[:]

	receivedAuthData := make([]byte, len(expectedAuthData))
	mesh.logger.Debugf(`waiting auth data from %v: %v`, stream.Conn().RemotePeer(), expectedAuthData)
	_, err = stream.Read(receivedAuthData)
	if err != nil {
		return
	}

	if bytes.Compare(expectedAuthData, receivedAuthData) != 0 {
		return errors.New("invalid signature")
	}
	return
}

func (mesh *Network) addStream(stream Stream, peerAddr AddrInfo) {
	mesh.logger.Debugf("addStream %v", stream.Conn().RemotePeer())
	if stream.Conn().RemotePeer() == mesh.ipfsNode.PeerHost.ID() {
		mesh.logger.Debugf("it's my ID, skip")
	}

	err := mesh.sendAuthData(stream)
	if err != nil {
		mesh.logger.Error(errors.Wrap(err))
		_ = stream.Close()
		return
	}

	err = mesh.recvAndCheckAuthData(stream)
	if err != nil {
		mesh.logger.Infof("invalid auth data: %v", err)
		_ = stream.Close()
		return
	}

	mesh.logger.Debugf(`a good stream, saving (remote peer: %v)`, stream.Conn().RemotePeer())
	mesh.streams.Store(stream.Conn().RemotePeer(), stream)

	for _, streamHandler := range mesh.streamHandlers {
		streamHandler.NewStream(stream, peerAddr)
	}
}
