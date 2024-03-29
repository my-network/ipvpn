package network

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	e "errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ipfs/go-cid"
	ipfsConfig "github.com/ipfs/go-ipfs-config"
	"github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/core/bootstrap"
	"github.com/ipfs/go-ipfs/plugin/loader"
	"github.com/ipfs/go-ipfs/repo"
	"github.com/ipfs/go-ipfs/repo/fsrepo"
	p2pcore "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	p2pprotocol "github.com/libp2p/go-libp2p-core/protocol"
	kbucket "github.com/libp2p/go-libp2p-kbucket"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"github.com/xaionaro-go/errors"
	"golang.org/x/sys/unix"

	"github.com/my-network/ipvpn/helpers"
)

const (
	p2pProtocolID  = p2pprotocol.ID(`/p2p/github.com/my-network/ipvpn`)
	ipvpnMagic     = "\000\314\326This is an InterPlanetary Virtual Private Network node"
	ipfsPortString = "24001"
)

const (
	enableQuic           = false
	sitSpotsPerPeerLimit = 16
	discoveryInterval    = time.Second * 10
)

var (
	addressExpireInterval = time.Hour * 24 * 30
	bufferSize            = 1 << 16
)

var (
	ErrPeerNotFound      = e.New(`peer not found`)
	ErrMessageTooShort   = e.New(`message too short`)
	ErrMessageTooLong    = e.New(`message too long`)
	ErrUnexpectedMessage = e.New(`unexpected message`)
	ErrNetworkIsNil      = e.New(`network is nil`)
)

type Network struct {
	cacheDir                   string
	logger                     Logger
	networkName                string
	publicSharedKeyword        []byte
	privateSharedKeyword       []byte
	ipfsNode                   *core.IpfsNode
	ipfsCfg                    *core.BuildCfg
	ipfsContext                context.Context
	ipfsContextCancelFunc      func()
	streamsLocker              sync.Mutex
	streams                    sync.Map
	streamHandlers             []StreamHandler
	callPathOptimizerCount     sync.Map
	badConnectionCount         sync.Map
	forbidOutcomingConnections sync.Map
	messageHandlerMap          sync.Map
	knownPeers                 KnownPeers
	knownPeersLocker           sync.RWMutex
	tryConnectChannel          chan AddrInfo
	discoveredPeerAddrs        *discoveredPeerAddrs
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
	result := ipfsConfig.Addresses{
		Swarm: []string{
			"/ip4/0.0.0.0/tcp/" + ipfsPortString,
			"/ip6/::/tcp/" + ipfsPortString,
			//
			// Also we need ICMP :(
		},
		Announce:   []string{},
		NoAnnounce: []string{},
		API:        ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/25001"},
		Gateway:    ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/28080"},
	}
	if enableQuic {
		result.Swarm = append(result.Swarm,
			"/ip4/0.0.0.0/udp/"+ipfsPortString+"/quic",
			"/ip6/::/udp/"+ipfsPortString+"/quic",
		)
	}
	return result
}

func initRepo(logger Logger, repoPath string, agreeToBeRelay bool) (err error) {
	defer func() { err = errors.Wrap(err) }()

	logger.Debugf(`generating keys`)

	privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, 521)
	if err != nil {
		return
	}

	privKeyBytes, err := crypto.MarshalPrivateKey(privKey)
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

	cfg := &ipfsConfig.Config{
		// see https://github.com/ipfs/go-ipfs/blob/master/docs/config.md

		Identity: identity,
		AutoNAT: ipfsConfig.AutoNATConfig{
			ServiceMode: ipfsConfig.AutoNATServiceEnabled,
		},
		Addresses: addressesConfig(),
		Bootstrap: ipfsConfig.BootstrapPeerStrings(bootstrapPeers),
		Mounts: ipfsConfig.Mounts{
			IPFS: "/ipfs",
			IPNS: "/ipns",
		},
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
			RelayClient: ipfsConfig.RelayClient{
				Enabled: ipfsConfig.True,
			},
			EnableRelayHop: agreeToBeRelay,
		},
		Experimental: ipfsConfig.Experiments{
			// https://github.com/ipfs/go-ipfs/blob/master/docs/experimental-features.md

			FilestoreEnabled: true,
		},
	}
	cfg.Swarm.Transports.Network.QUIC = ipfsConfig.True
	err = fsrepo.Init(repoPath, cfg)
	if err != nil {
		return
	}

	return
}

func New(networkName string, psk []byte, cacheDir string, agreeToBeRelay bool, logger Logger, streamHandlers ...StreamHandler) (mesh *Network, err error) {
	defer func() {
		if err != nil {
			mesh = nil
			err = errors.Wrap(err)
		}
	}()

	logger.Debugf(`loading IPFS plugins`)

	pluginLoader, err := loader.NewPluginLoader(``)
	if err != nil {
		return
	}
	err = pluginLoader.Initialize()
	if err != nil {
		return
	}
	err = pluginLoader.Inject()
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

		err = initRepo(logger, repoPath, agreeToBeRelay)
		if err != nil {
			return
		}
	}

	logger.Debugf(`loading "known_peers.json"`)

	knownPeers := KnownPeers{}
	{
		knownPeersJSON, knownPeersReadError := ioutil.ReadFile(filepath.Join(cacheDir, `known_peers.json`))
		logger.Debugf(`loading "known_peers.json" err == %v`, knownPeersReadError)
		if knownPeersReadError == nil {
			knownPeersParseError := json.Unmarshal(knownPeersJSON, &knownPeers)
			if knownPeersParseError != nil {
				logger.Error(errors.Wrap(knownPeersParseError, `unable to parse "known_peers.json"`))
			}
		}
	}

	logger.Debugf(`loading "swarm_peers.json"`)

	var swarmAddrInfos []AddrInfo
	{
		swarmAddrInfosJSON, swarmAddrInfosReadError := ioutil.ReadFile(filepath.Join(cacheDir, `swarm_peers.json`))
		logger.Debugf(`loading "swarm_peers.json" err == %v`, swarmAddrInfosReadError)
		if swarmAddrInfosReadError == nil {
			swarmAddrInfosParseError := json.Unmarshal(swarmAddrInfosJSON, &swarmAddrInfos)
			if swarmAddrInfosParseError != nil {
				logger.Error(errors.Wrap(swarmAddrInfosParseError, `unable to parse "known_peers.json"`))
			}
		}
	}

	logger.Debugf(`opening the repository "%v"`, repoPath)

	var ipfsRepo repo.Repo
	ipfsRepo, err = fsrepo.Open(repoPath)
	if err != nil {
		return
	}

	ipfsRepoConfig, err := ipfsRepo.Config()
	if err != nil {
		return
	}

	if len(knownPeers) > 0 {
		logger.Debugf(`fixing the repository's config: adding known peers' (count: %v) addresses to bootstrap nodes`, len(knownPeers))

		for _, knownPeer := range knownPeers {
			sitSpots := knownPeer.SitSpots
			if len(sitSpots) > sitSpotsPerPeerLimit {
				sitSpots = sitSpots[:sitSpotsPerPeerLimit]
			}
			for _, sitSpot := range sitSpots {
				for maddrString, lastSeenTS := range sitSpot.Addresses {
					if time.Since(lastSeenTS) > addressExpireInterval {
						continue
					}
					maddr, err := multiaddr.NewMultiaddr(maddrString)
					if err != nil {
						logger.Error(errors.Wrap(err, `unable to parse MultiAddr`, maddrString))
						continue
					}
					if ipString, err := maddr.ValueForProtocol(multiaddr.P_IP4); err == nil {
						if net.ParseIP(ipString).IsLoopback() {
							continue
						}
					}
					if ipString, err := maddr.ValueForProtocol(multiaddr.P_IP6); err == nil {
						if net.ParseIP(ipString).IsLoopback() {
							continue
						}
					}

					peerString := maddr.String() + `/ipfs/` + knownPeer.ID.String()

					found := false
					for _, bootstrapPeer := range ipfsRepoConfig.Bootstrap {
						if bootstrapPeer == peerString {
							found = true
							break
						}
					}

					if !found {
						ipfsRepoConfig.Bootstrap = append(ipfsRepoConfig.Bootstrap, peerString)
					}
				}
			}
		}
	}

	if len(swarmAddrInfos) > 0 {
		logger.Debugf(`fixing the repository's config: previous swam peers' (count: %v) addresses to bootstrap nodes`, len(swarmAddrInfos))

		for _, addrInfo := range swarmAddrInfos {
			for _, maddr := range addrInfo.Addrs {
				found := false
				peerAddr := maddr.String() + `/ipfs/` + addrInfo.ID.String()
				for _, bootstrapPeer := range ipfsRepoConfig.Bootstrap {
					if bootstrapPeer == peerAddr {
						found = true
						break
					}
				}

				if !found {
					ipfsRepoConfig.Bootstrap = append(ipfsRepoConfig.Bootstrap, peerAddr)
				}
			}
		}
	}

	logger.Debugf(`bootstrap nodes: %v`, ipfsRepoConfig.Bootstrap)

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
		cancelFunc()
		return
	}

	mesh = &Network{
		cacheDir:              cacheDir,
		logger:                logger,
		networkName:           networkName,
		publicSharedKeyword:   generatePublicSharedKeyword(networkName, psk),
		privateSharedKeyword:  generatePrivateSharedKeyword(networkName, psk),
		ipfsNode:              ipfsNode,
		ipfsCfg:               ipfsCfg,
		ipfsContext:           ctx,
		ipfsContextCancelFunc: cancelFunc,
		streamHandlers:        streamHandlers,
		knownPeers:            knownPeers,
		tryConnectChannel:     make(chan AddrInfo),
	}
	mesh.discoveredPeerAddrs = newDiscoveredPeerAddrs(mesh)

	err = mesh.start()
	if err != nil {
		_ = mesh.Close()
		return
	}

	return
}

type addrInfoWithLatencies struct {
	Network            *Network
	BadConnectionCount []uint64
	Latencies          []time.Duration
	AddrInfo           *AddrInfo
}

func (data *addrInfoWithLatencies) Len() int { return len(data.AddrInfo.Addrs) }
func (data *addrInfoWithLatencies) Less(i, j int) bool {
	if data.BadConnectionCount[i] != data.BadConnectionCount[j] {
		return data.BadConnectionCount[i] < data.BadConnectionCount[j]
	}
	ipA, errA := data.AddrInfo.Addrs[i].ValueForProtocol(multiaddr.P_IP4)
	ipB, errB := data.AddrInfo.Addrs[j].ValueForProtocol(multiaddr.P_IP4)
	if errA == nil && errB == nil && ipA == ipB {
		_, udpAErr := data.AddrInfo.Addrs[i].ValueForProtocol(multiaddr.P_UDP)
		_, udpBErr := data.AddrInfo.Addrs[j].ValueForProtocol(multiaddr.P_UDP)
		if udpAErr == nil && udpBErr != nil {
			return true
		}
		return false
	}
	return data.Latencies[i] < data.Latencies[j]
}
func (data *addrInfoWithLatencies) Swap(i, j int) {
	data.BadConnectionCount[i], data.BadConnectionCount[j] = data.BadConnectionCount[j], data.BadConnectionCount[i]
	data.Latencies[i], data.Latencies[j] = data.Latencies[j], data.Latencies[i]
	data.AddrInfo.Addrs[i], data.AddrInfo.Addrs[j] = data.AddrInfo.Addrs[j], data.AddrInfo.Addrs[i]
}

func (mesh *Network) tryConnectByOptimalPath(stream Stream, addrInfo *AddrInfo, isIncoming bool) Stream {

	// Removing bad addresses
	{
		var maddrs []multiaddr.Multiaddr
		for _, maddr := range addrInfo.Addrs {
			isBad := false
			if isBad == false {
				if ip, err := maddr.ValueForProtocol(multiaddr.P_IP4); err == nil {
					if net.ParseIP(ip).IsLoopback() {
						mesh.logger.Debugf(`Address %v is a loopback address, skipping`, maddr)
						isBad = true
					}
				}
			}
			if isBad == false {
				if ip, err := maddr.ValueForProtocol(multiaddr.P_IP6); err == nil {
					if net.ParseIP(ip).IsLoopback() {
						mesh.logger.Debugf(`Address %v is a loopback address, skipping`, maddr)
						isBad = true
					}
				}
			}
			if isBad == false {
				for _, streamHandler := range mesh.streamHandlers {
					if streamHandler.IsBadAddress(maddr) {
						mesh.logger.Debugf(`Address %v is banned by stream handler %v`, maddr, streamHandler.ProtocolID())
						isBad = true
						break
					}
				}
			}
			if isBad {
				continue
			}
			mesh.logger.Debugf(`Address %v is good, adding to the list`, maddr)
			maddrs = append(maddrs, maddr)
		}
		addrInfo.Addrs = maddrs
	}

	// Init data
	data := addrInfoWithLatencies{
		Network:            mesh,
		BadConnectionCount: make([]uint64, len(addrInfo.Addrs)),
		Latencies:          make([]time.Duration, len(addrInfo.Addrs)),
		AddrInfo:           addrInfo,
	}

	for idx, addr := range addrInfo.Addrs {
		badConnectionCount, ok := mesh.badConnectionCount.Load(addr.String())
		if !ok {
			continue
		}
		data.BadConnectionCount[idx] = badConnectionCount.(uint64)
	}

	// Measure latencies
	measureLatencyContext, cancelFunc := context.WithTimeout(context.Background(), time.Second)
	defer cancelFunc()
	for idx, addr := range addrInfo.Addrs {
		data.Latencies[idx] = math.MaxInt64

		go func(idx int, addr p2pcore.Multiaddr) {
			latency := mesh.measureLatencyToMultiaddr(measureLatencyContext, addr)
			select {
			case <-measureLatencyContext.Done():
			default:
				data.Latencies[idx] = latency
			}
		}(idx, addr)
		go func(idx int, addr p2pcore.Multiaddr) {
			addr4, err := addr.ValueForProtocol(multiaddr.P_IP4)
			if err != nil {
				return
			}
			port, err := addr.ValueForProtocol(multiaddr.P_TCP)
			if err != nil {
				return
			}
			data.BadConnectionCount[idx]++
			conn, err := net.DialTimeout("tcp", addr4+":"+port, time.Second)
			if err == nil {
				select {
				case <-measureLatencyContext.Done():
				default:
					data.BadConnectionCount[idx]--
				}
				_ = conn.Close()
			}
		}(idx, addr)
	}
	<-measureLatencyContext.Done()

	// Prioritize paths
	sort.Sort(&data)
	mesh.logger.Debugf("prioritized paths %v %v %v", data.BadConnectionCount, data.Latencies, data.AddrInfo.Addrs)

	// Set new addrs
	mesh.ipfsNode.PeerHost.Network().Peerstore().SetAddrs(addrInfo.ID, data.AddrInfo.Addrs, time.Minute*5)

	if stream != nil &&
		data.AddrInfo.Addrs[0].String() != stream.Conn().RemoteMultiaddr().String() &&
		(isIncoming && strings.HasSuffix(stream.Conn().RemoteMultiaddr().String(), `/quic`)) {

		var msg [9]byte
		msg[0] = byte(MessageTypeStopConnectionOnYourSide)
		mesh.logger.Infof("sending status data: %v %v", msg[0], uint64(data.Latencies[0]))
		binary.LittleEndian.PutUint64(msg[1:], uint64(data.Latencies[0]))
		_, err := stream.Write(msg[:])
		if err != nil {
			mesh.logger.Infof("unable to send status data: %v", errors.Wrap(err))
		}

		mesh.logger.Infof("receiving status data")
		_, err = stream.Read(msg[:])
		if err != nil {
			mesh.logger.Infof("unable to receive status data: %v", errors.Wrap(err))
		}
		msgType := MessageType(msg[0])
		latency := time.Duration(binary.LittleEndian.Uint64(msg[1:]))
		mesh.logger.Infof("received status data: %v %v", msgType, latency)

		if latency == data.Latencies[0] {
			mesh.logger.Infof("equal latencies, I was wrong: %v %v", latency, data.Latencies[0])
			return stream
		}

		if latency < data.Latencies[0] {
			mesh.logger.Infof("my latency is higher, I was wrong: %v %v", latency, data.Latencies[0])
			if msgType == MessageTypeStopConnectionOnYourSide {
				mesh.logger.Debugf("ignoring connection %v by remote request", stream.Conn().RemoteMultiaddr().String())
				return nil
			}
			return stream
		}

		mesh.logger.Debugf("closing connection %v (!= %v)", stream.Conn().RemoteMultiaddr().String(), data.AddrInfo.Addrs[0].String())
		_ = stream.Conn().Close()

		stream = nil
	}

	if stream == nil {
		mesh.logger.Debugf("stream == nil, Connect(), NewStream(): %v", *addrInfo)
		var err error
		err = mesh.ipfsNode.PeerHost.Connect(mesh.ipfsContext, *addrInfo)
		if err != nil {
			mesh.logger.Debugf("unable to connect to %v: %v", addrInfo.ID, errors.Wrap(err))
		}
		stream, err = mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, addrInfo.ID, p2pProtocolID)
		if err != nil {
			mesh.logger.Debugf("%v", errors.Wrap(err))
			mesh.logger.Infof("unable create a new stream to %v: %v (%v)", addrInfo.ID, err, fmt.Sprintf("%T", err))
			return nil
		}
	}

	var msg [9]byte
	msg[0] = byte(MessageTypeOK)
	mesh.logger.Infof("sending status data %v %v", msg[0], uint64(data.Latencies[0]))
	binary.LittleEndian.PutUint64(msg[1:], uint64(data.Latencies[0]))
	_, err := stream.Write(msg[:])
	if err != nil {
		mesh.logger.Infof("unable to send status data: %v", errors.Wrap(err))
	}

	mesh.logger.Infof("receiving status data")
	_, err = stream.Read(msg[:])
	if err != nil {
		mesh.logger.Infof("unable to receive status data: %v", errors.Wrap(err))
	}
	msgType := MessageType(msg[0])
	latency := time.Duration(binary.LittleEndian.Uint64(msg[1:]))

	mesh.logger.Infof("received status data: %v %v", msgType, latency)
	switch msgType {
	case MessageTypeOK:
	case MessageTypeStopConnectionOnYourSide:
		mesh.logger.Infof("remote side wishes to initiate connection from it's side")
		if latency >= data.Latencies[0] {
			mesh.logger.Infof("their latency is higher, not complying: %v %v", latency, data.Latencies[0])
			return stream
		}
		_ = stream.Close()
		return nil
	}

	return stream
}

func (mesh *Network) considerPeerAddr(peerAddr AddrInfo) {
	peerID := peerAddr.ID

	if peerID == mesh.ipfsNode.PeerHost.ID() {
		if len(peerAddr.Addrs) == 0 {
			mesh.logger.Debugf(`len(peerAddr.Addrs) == 0`)
			return
		}
		//mesh.logger.Debugf("my ID, notifing stream handlers about my addrInfo: %v", peerAddr.Addrs)
		return
	}

	mesh.logger.Debugf("found peer: %v: %v", peerID, peerAddr.Addrs)

	// Removing addresses of myself from peer's addresses
	{
		listenAddresses, err := mesh.ipfsNode.PeerHost.Network().InterfaceListenAddresses()
		if err != nil {
			mesh.logger.Error(errors.Wrap(err))
		}
		m := map[string]struct{}{}
		for _, addr := range listenAddresses {
			m[addr.String()] = struct{}{}
		}
		/*myAddresses := mesh.ipfsNode.PeerHost.Addrs()
		for _, addr := range myAddresses {
			m[addr.String()] = struct{}{}
		}*/

		var cleanAddrs []multiaddr.Multiaddr
		for _, addr := range peerAddr.Addrs {
			if _, ok := m[addr.String()]; ok {
				continue
			}
			cleanAddrs = append(cleanAddrs, addr)
		}
		peerAddr.Addrs = cleanAddrs
	}

	// if no addresses provided then try to find them via DHT

	if len(peerAddr.Addrs) == 0 {
		mesh.logger.Debugf(`mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, "%v")...`, peerID)
		var err error
		peerAddr, err = mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerID)
		if err != nil {
			mesh.logger.Infof("unable to find a route to peer %v: %v", peerID, err)
			return
		}
		mesh.logger.Debugf("peer's addresses: %v", peerAddr.Addrs)
	}

	go func(addrInfo *AddrInfo) {
		mesh.tryConnectChannel <- *addrInfo
	}(helpers.CopyAddrInfo(peerAddr))
}

func (mesh *Network) pubSubBasedConnector(ipfsCid cid.Cid) {
	subscription, err := mesh.ipfsNode.PubSub.Subscribe(ipfsCid.String())
	if err != nil {
		mesh.logger.Error(errors.Wrap(err, `unable to subscriber via PubSub`))
		return
	}
	for {
		msg, err := subscription.Next(mesh.ipfsContext)
		if err != nil {
			mesh.logger.Debugf("subscription.Next() -> %v", err)
			return
		}

		sourceID := msg.GetFrom()
		mesh.logger.Debugf(`got pubsub message from %v`, sourceID)
		addrInfo, err := mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, sourceID)
		if err != nil {
			mesh.logger.Debugf(`pubSubBasedConnector: FindPeer(..., "%v"): %v`, sourceID, err)
			continue
		}

		mesh.logger.Debugf(`pubSubBasedConnector: considerPeerAddr...`)
		mesh.considerPeerAddr(addrInfo)
	}
}

func (mesh *Network) dhtBasedConnector(ipfsCid cid.Cid) {
	mesh.logger.Debugf(`initializing output streams`)

	provChan := mesh.ipfsNode.DHT.FindProvidersAsync(mesh.ipfsContext, ipfsCid, 1<<16)
	count := uint(0)
	for {
		select {
		case <-mesh.ipfsContext.Done():
			return
		case peerAddr := <-provChan:
			if peerAddr.ID == "" {
				hours := (1 << count) - 1
				mesh.logger.Debugf("empty peer ID, sleep %v hours and restart FindProvidersAsync", hours)
				time.Sleep(time.Hour * time.Duration(hours))
				provChan = mesh.ipfsNode.DHT.FindProvidersAsync(mesh.ipfsContext, ipfsCid, 1<<16)
				count++
				continue
			}

			if peerAddr.ID == mesh.ipfsNode.Identity {
				for _, streamHandler := range mesh.streamHandlers {
					streamHandler.SetMyAddrs(peerAddr.Addrs)
				}
				continue
			}

			go mesh.considerPeerAddr(peerAddr)
		}
	}
}

func (mesh *Network) SetMessageHandler(topic string, handler func(Stream, []byte)) {
	if _, loaded := mesh.messageHandlerMap.LoadOrStore(topic, handler); loaded {
		panic(`a message handler is already set for topic ` + topic)
	}
}

var (
	sendMessageBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, bufferSize)
			return &b
		},
	}
)

func (mesh *Network) SendBroadcastMessage(topic string, msg []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if mesh == nil {
		return ErrNetworkIsNil
	}

	mesh.streams.Range(func(key, value interface{}) bool {
		peerID := key.(p2pcore.PeerID)
		newErr := mesh.SendMessage(peerID, topic, msg)
		if newErr != nil {
			err = newErr
		}
		return true
	})

	return
}

func (mesh *Network) SendMessage(peerID peer.ID, topic string, msg []byte) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if len(topic)+len(msg)+6 >= bufferSize {
		return ErrMessageTooLong
	}

	streamI, _ := mesh.streams.Load(peerID)
	if streamI == nil {
		return ErrPeerNotFound
	}
	stream := streamI.(Stream)

	bufPtr := sendMessageBufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf[0] = uint8(MessageTypeCustom)
	binary.LittleEndian.PutUint16(buf[1:], uint16(len(topic)))
	copy(buf[1+2:], topic)
	binary.LittleEndian.PutUint16(buf[1+2+len(topic):], uint16(len(msg)))
	copy(buf[1+2+len(topic)+2:], msg)
	_, err = stream.Write(buf[:1+2+len(topic)+2+len(msg)])
	sendMessageBufferPool.Put(bufPtr)
	return err
}

func (mesh *Network) onReceiveMessageCustom(stream Stream, topic string, payload []byte) {
	messageHandlerI, loaded := mesh.messageHandlerMap.Load(topic)
	if !loaded {
		mesh.logger.Infof(`Received a message with topic "%v" from %v, but I don't know what to do with it`, topic, stream.Conn().RemotePeer())
		return
	}
	messageHandler := messageHandlerI.(func(Stream, []byte))
	mesh.logger.Debugf(`found a message handler for topic "%v" and payload: %X`, topic, payload)
	messageHandler(stream, payload)
}

func (mesh *Network) streamHandler(stream Stream) {
	defer mesh.logger.Debugf(`endof streamHandler for %v, stream.ID:%v`, stream.Conn().RemotePeer(), stream.ID())

	buf := make([]byte, bufferSize)

streamHandlerLoop:
	for {
		n, err := stream.Read(buf[:1])
		if err != nil {
			mesh.logger.Infof(`a control stream (%v) to peer %v closed while reading message type: %v (%T)`, stream.ID(), stream.Conn().RemotePeer(), err, err)
			break
		}

		if n < 1 {
			mesh.logger.Error(errors.Wrap(ErrMessageTooShort, n))
			continue
		}

		msgType := MessageType(buf[0])
		switch msgType {
		case MessageTypeCustom:
			n, err := stream.Read(buf[:2])
			if err != nil {
				mesh.logger.Infof(`a control stream (%v) to peer %v closed while reading topic name length: %v (%T)`, stream.ID(), stream.Conn().RemotePeer(), err, err)
				break streamHandlerLoop
			}
			payload := buf[0:n]

			if len(payload) < 2 {
				mesh.logger.Error(errors.Wrap(ErrMessageTooShort, n))
				continue
			}

			topicLength := binary.LittleEndian.Uint16(payload)

			n, err = stream.Read(buf[:topicLength])
			if err != nil {
				mesh.logger.Infof(`a control stream (%v) to peer %v closed while reading topic name: %v (%T)`, stream.ID(), stream.Conn().RemotePeer(), err, err)
				break streamHandlerLoop
			}
			payload = buf[0:n]

			if len(payload) < int(topicLength) {
				mesh.logger.Error(errors.Wrap(ErrMessageTooShort, n, len(payload), topicLength))
				continue
			}

			topic := string(payload[:topicLength])

			n, err = stream.Read(buf[:2])
			if err != nil {
				mesh.logger.Infof(`a control stream (%v) to peer %v closed while reading payload length: %v (%T)`, stream.ID(), stream.Conn().RemotePeer(), err, err)
				break streamHandlerLoop
			}
			payload = buf[0:n]

			payloadLength := binary.LittleEndian.Uint16(payload)

			n, err = stream.Read(buf[:payloadLength])
			if err != nil {
				mesh.logger.Infof(`a control stream (%v) to peer %v closed while reading payload: %v (%T)`, stream.ID(), stream.Conn().RemotePeer(), err, err)
				break streamHandlerLoop
			}
			payload = buf[0:payloadLength]

			if len(payload) < int(payloadLength) {
				mesh.logger.Error(errors.Wrap(ErrMessageTooShort, n, len(payload), payloadLength))
				continue
			}

			mesh.logger.Debugf(`received a custom message with topic "%v" from %v, payload: %v %v`, topic, stream.Conn().RemotePeer(), string(payload), payload)
			mesh.onReceiveMessageCustom(stream, topic, payload)
		default:
			mesh.logger.Error(errors.Wrap(ErrUnexpectedMessage, msgType))
			_, _ = stream.Read(buf)
		}
	}

	mesh.logger.Debugf(`stream.Close(): stream.ID:%v`, stream.ID())
	_ = stream.Close()
	_ = stream.Conn().Close()

	mesh.streamsLocker.Lock()
	streamI, _ := mesh.streams.Load(stream.Conn().RemotePeer())
	if streamI == stream {
		mesh.streams.Delete(stream.Conn().RemotePeer())
	}
	mesh.streamsLocker.Unlock()
}

func (mesh *Network) tryConnectChannelHandler() {
	var tryConnectMutex sync.Mutex
	isAlreadyTrying := map[peer.ID]bool{}
	pendingTries := map[peer.ID]*AddrInfo{}

	for {
		select {
		case <-mesh.ipfsContext.Done():
			return
		case addrInfo := <-mesh.tryConnectChannel:
			mesh.logger.Debugf(`got an addrInfo from tryConnectChannel: %v`, addrInfo)

			tryConnectMutex.Lock()
			if isAlreadyTrying[addrInfo.ID] {
				mesh.logger.Debugf(`already trying to connect to %v, pending`, addrInfo.ID)
				pendingTries[addrInfo.ID] = &addrInfo
				tryConnectMutex.Unlock()
				continue
			}
			tryConnectMutex.Unlock()

			oldStreamI, _ := mesh.streams.Load(addrInfo.ID)
			if oldStreamI != nil {
				if mesh.ipfsNode.PeerHost.Network().Connectedness(addrInfo.ID) == network.Connected {
					mesh.logger.Debugf(`tryConnectChannelHandler(): already connected to %v, skipping`, addrInfo.ID)
					continue
				}
				mesh.logger.Debugf(`strange, we have a stream, but not connected to %v. Reconnecting`, addrInfo.ID)
				oldStream := oldStreamI.(Stream)
				_ = oldStream.Close()
			}

			isAlreadyTrying[addrInfo.ID] = true
			go func(addrInfo AddrInfo) {
				mesh.tryConnect(addrInfo)

				tryConnectMutex.Lock()
				defer tryConnectMutex.Unlock()

				delete(isAlreadyTrying, addrInfo.ID)
				pendingAddrInfo := pendingTries[addrInfo.ID]
				if pendingAddrInfo != nil {
					delete(pendingTries, addrInfo.ID)
					mesh.logger.Debugf(`resending to tryConnectChannel a pending try to connect to: %v`, addrInfo)
					go func(addrInfo *AddrInfo) {
						mesh.tryConnectChannel <- *addrInfo
					}(helpers.CopyAddrInfo(*pendingAddrInfo))
				}
			}(addrInfo)
		}
	}
}

func (mesh *Network) start() (err error) {
	defer func() { err = errors.Wrap(err) }()

	mesh.logger.Debugf(`running tryConnect channel handler`)

	go mesh.tryConnectChannelHandler()

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
		streamHandler.SetNetwork(mesh)
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

	listenAddresses, err := mesh.ipfsNode.PeerHost.Network().InterfaceListenAddresses()
	if err != nil {
		mesh.logger.Error(errors.Wrap(err))
	}
	mesh.logger.Debugf(`registering local discovery handler. listenAddresses == %v`, listenAddresses)

	if mesh.ipfsNode.Discovery != nil {
		panic("mesh.ipfsNode.Discovery != nil")
	}
	discovery := discovery.NewMdnsService(mesh.ipfsNode.PeerHost, "_ipfs-ipvpn-discovery._udp", mesh)
	err = discovery.Start()
	if err == nil {
		mesh.ipfsNode.Discovery = discovery
		go func() {
			<-mesh.ipfsContext.Done()
			mesh.logger.Debugf(`mesh.ipfsContext is closed, closing the discovery services`)
			mesh.ipfsNode.Discovery.Close()
			mesh.ipfsNode.Discovery = nil
		}()
	} else {
		mesh.logger.Error(errors.Wrap(err))
	}

	// mesh.discoveredPeerAddrs.GC
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-mesh.ipfsContext.Done():
				return
			case <-ticker.C:
				mesh.discoveredPeerAddrs.GC()
			}
		}
	}()

	mesh.logger.Debugf(`starting to listen for the input streams handler`)

	mesh.ipfsNode.PeerHost.SetStreamHandler(p2pProtocolID, func(stream Stream) {
		peerID := stream.Conn().RemotePeer()
		mesh.logger.Debugf("incoming connection from %v %v", peerID, stream.Conn().RemoteMultiaddr())

		addrInfo, err := mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerID)
		if err != nil {
			mesh.logger.Error(errors.Wrap(err, peerID))
			err := stream.Conn().Close()
			if err != nil {
				mesh.logger.Error(errors.Wrap(err))
			}
			return
		}

		stream = mesh.tryConnectByOptimalPath(stream, &addrInfo, true)
		if stream == nil {
			mesh.logger.Debugf("no opened stream, skip")
			return
		}

		/*var callPathOptimizerCount uint64
		if v, ok := mesh.callPathOptimizerCount.Load(peerID); ok {
			callPathOptimizerCount = v.(uint64)
		}
		if callPathOptimizerCount == 0 {
			go func() {
				time.Sleep(time.Hour)
				mesh.callPathOptimizerCount.Store(peerID, uint64(0))
			}()
		}
		var shouldContinue, alreadyOptimal bool
		if callPathOptimizerCount < 5 {
			shouldContinue, alreadyOptimal = mesh.tryConnectByOptimalPath(stream, &addrInfo, true)
			if !shouldContinue {
				return
			}
			mesh.callPathOptimizerCount.Store(peerID, callPathOptimizerCount+1)
		} else {
			alreadyOptimal = true
		}
		if !alreadyOptimal {
			stream, err = mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, p2pProtocolID)
			if err != nil {
				mesh.logger.Debugf("got error from NewStream: %v", err)
				return
			}
		}*/
		err = mesh.addStream(stream, addrInfo)
		if err != nil {
			mesh.logger.Debugf("got error from addStream: %v", err)
			return
		}
		mesh.logger.Debugf("success %v", peerID)
	})

	for _, streamHandler := range mesh.streamHandlers {
		func(streamHandler StreamHandler) {
			mesh.ipfsNode.PeerHost.SetStreamHandlerMatch(streamHandler.ProtocolID(), func(s string) bool {
				isMatch := strings.HasPrefix(s, string(streamHandler.ProtocolID()))
				mesh.logger.Debugf("StreamHandlerMatch: %v %v %v", s, streamHandler.ProtocolID(), isMatch)
				return isMatch
			}, func(stream Stream) {
				peerID := stream.Conn().RemotePeer()
				mesh.logger.Debugf(`NewStream for %v from %v`, stream.Protocol(), peerID)
				streamHandler.NewIncomingStream(stream, AddrInfo{ID: peerID})
			})
			mesh.logger.Debugf(`Registered a stream handler for %v`, streamHandler.ProtocolID())
		}(streamHandler)
	}
	mesh.logger.Debugf(`In total registered stream handlers for %v`, mesh.ipfsNode.PeerHost.Mux().Protocols())

	go func() {
		mesh.logger.Debugf(`Notifying streamHandlers (such as VPN handler) about previously known peers (count == %v)`, len(mesh.knownPeers))
		mesh.knownPeersLocker.RLock()
		defer mesh.knownPeersLocker.RUnlock()

		for _, knownPeer := range mesh.knownPeers {
			var addresses []multiaddr.Multiaddr
			for _, sitSpot := range knownPeer.SitSpots {
				for maddrString, lastSeenTS := range sitSpot.Addresses {
					if time.Since(lastSeenTS) > addressExpireInterval {
						continue
					}
					maddr, err := multiaddr.NewMultiaddr(maddrString)
					if err != nil {
						mesh.logger.Error(errors.Wrap(err, `unable to parse MultiAddr`, maddrString))
					}
					addresses = append(addresses, maddr)
				}
			}
			for _, streamHandler := range mesh.streamHandlers {
				streamHandler.ConsiderKnownPeer(AddrInfo{ID: knownPeer.ID, Addrs: addresses})
			}
		}
	}()

	go mesh.updateMyAddrInfo()

	go func() {
		for i := 0; i < 120; i++ {
			time.Sleep(time.Second)
			mesh.updateMyAddrInfo()
		}
	}()

	go mesh.dhtBasedConnector(ipfsCid)
	go mesh.pubSubBasedConnector(ipfsCid)

	mesh.logger.Infof(`My ID: %v        Calling IPFS "DHT.Provide()"/"PubSub.Publish()" on the shared key (that will be used for the node discovery), Cid: %v`, mesh.ipfsNode.PeerHost.ID(), ipfsCid)

	mesh.logger.Debugf("Routing.Publish()...")
	err = mesh.ipfsNode.PubSub.Publish(ipfsCid.String(), ipfsCid.Bytes())
	if err != nil {
		mesh.logger.Debugf("Routing.Publish() -> %v", err)
	}
	for i := 1; i < 120; i++ {
		err = mesh.ipfsNode.Routing.Bootstrap(mesh.ipfsContext)
		if err != nil {
			mesh.logger.Debugf("mesh.ipfsNode.Routing.Bootstrap(mesh.ipfsContext) -> %v", err)
		}

		mesh.logger.Debugf("Routing.Provide()")
		err = mesh.ipfsNode.Routing.Provide(mesh.ipfsContext, ipfsCid, true)
		if err == kbucket.ErrLookupFailure {
			mesh.logger.Debugf("Got kbucket.ErrLookupFailure, retry in one second. It was try #%v", i)
			err = mesh.ipfsNode.Bootstrap(bootstrap.BootstrapConfig{
				ConnectionTimeout: time.Duration(i) * time.Second,
				MinPeerThreshold:  10,
				Period:            time.Minute,
			})
			if err != nil {
				mesh.logger.Debugf("unable to re-bootstrap: %v", err)
			}
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return
	}

	mesh.logger.Debugf(`started an IPFS node`)

	go func() {
		time.Sleep(time.Minute * 5)
		mesh.updateMyAddrInfo()
	}()

	go func() {
		go mesh.updateMyAddrInfo()
		ticker := time.NewTicker(time.Hour)
		for {
			select {
			case <-ticker.C:
			}
			go mesh.updateMyAddrInfo()
			mesh.saveSwarmPeersAsBootstrapPeers()
		}
	}()

	return
}

func (mesh *Network) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()
	mesh.logger.Debugf(`closing an IPFS node`)
	mesh.ipfsContextCancelFunc()
	return mesh.ipfsNode.Close()
}

func (mesh *Network) tryConnect(addrInfo AddrInfo) {
	mesh.logger.Debugf("tryConnect: %v: tryConnectByOptimalPath", addrInfo.ID)
	stream := mesh.tryConnectByOptimalPath(nil, &addrInfo, false)

	if stream != nil {
		mesh.logger.Debugf("tryConnect: %v: add stream", addrInfo.ID)
		if err := mesh.addStream(stream, addrInfo); err != nil {
			mesh.logger.Error(errors.Wrap(err))
			return
		}
	}

	mesh.logger.Debugf("tryConnect: %v: end", addrInfo.ID)
}

func (mesh *Network) handlePeerFound(addrInfo peer.AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()
	mesh.logger.Debugf("handlerPeerFound: %v", addrInfo.ID)

	if enableQuic {
		// MDNS discovery doesn't propose any connection using QUIC, so we add it manually:
		if len(addrInfo.Addrs) == 1 {
			maddr := addrInfo.Addrs[0]
			if tcpPort, tcpErr := maddr.ValueForProtocol(multiaddr.P_TCP); tcpErr == nil {
				ipString, ipErr := maddr.ValueForProtocol(multiaddr.P_IP4)
				if ipErr == nil {
					newMaddr, err := multiaddr.NewMultiaddr(`/ip4/` + ipString + `/udp/` + tcpPort + `/quic`)
					if err != nil {
						mesh.logger.Error(errors.Wrap(err))
					} else {
						addrInfo.Addrs = append(addrInfo.Addrs, newMaddr)
					}
				}
			}
		}
	}

	mesh.discoveredPeerAddrs.OfPeer(addrInfo.ID).AccumulateAddrs(addrInfo.Addrs)
	return
}

// this method is called by the IPFS Discovery service directly.
func (mesh *Network) HandlePeerFound(addrInfo peer.AddrInfo) {
	if err := mesh.handlePeerFound(addrInfo); err != nil {
		mesh.logger.Error(errors.Wrap(err))
	}
}

func (mesh *Network) saveSwarmPeersAsBootstrapPeers() {
	err := mesh.doSaveSwarmPeersAsBootstrapPeers()
	if err != nil {
		mesh.logger.Error(errors.Wrap(err))
	}
}

func (mesh *Network) doSaveSwarmPeersAsBootstrapPeers() (err error) {
	defer func() { err = errors.Wrap(err) }()

	mesh.logger.Debugf(`doSaveSwarmPeersAsBootstrapPeers()`)

	var addrInfos []*AddrInfo
	for _, conn := range mesh.ipfsNode.PeerHost.Network().Conns() {
		peerID := conn.RemotePeer()
		addr := conn.RemoteMultiaddr()
		var addrInfo *AddrInfo
		for _, cmpAddrInfo := range addrInfos {
			if cmpAddrInfo.ID == peerID {
				addrInfo = cmpAddrInfo
				break
			}
		}

		if addrInfo == nil {
			addrInfo = &AddrInfo{ID: peerID}
			addrInfos = append(addrInfos, addrInfo)
		}

		found := false
		for _, cmpAddr := range addrInfo.Addrs {
			if cmpAddr.Equal(addr) {
				found = true
				break
			}
		}
		if !found {
			addrInfo.Addrs = append(addrInfo.Addrs, addr)
		}
	}

	addrInfosJSON, err := json.Marshal(addrInfos)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(filepath.Join(mesh.cacheDir, `swarm_peers.json`), addrInfosJSON, 0640)
	if err != nil {
		return
	}

	return
}

func (mesh *Network) updateMyAddrInfo() {
	//mesh.logger.Debugf(`updating my AddrInfo...`)
	mesh.considerPeerAddr(AddrInfo{
		ID:    mesh.ipfsNode.PeerHost.ID(),
		Addrs: mesh.ipfsNode.PeerHost.Addrs(),
	})
}

func (mesh *Network) sendAuthData(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

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
	defer func() { err = errors.Wrap(err) }()

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

	if !bytes.Equal(expectedAuthData, receivedAuthData) {
		return errors.Errorf("invalid signature, expected:%X, received:%X", expectedAuthData, receivedAuthData)
	}
	return
}

func (mesh *Network) saveIPFSRepositoryConfig(cfg *ipfsConfig.Config) (err error) {
	defer func() { err = errors.Wrap(err) }()

	err = mesh.ipfsNode.Repo.SetConfig(cfg)
	if err != nil {
		return
	}

	return
}

func (mesh *Network) addToKnownPeers(peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	mesh.knownPeersLocker.Lock()
	defer mesh.knownPeersLocker.Unlock()

	if mesh.knownPeers == nil {
		mesh.knownPeers = KnownPeers{}
	}

	knownPeer := mesh.knownPeers[peerAddr.ID]
	if knownPeer == nil {
		knownPeer = &KnownPeer{ID: peerAddr.ID}
		mesh.knownPeers[peerAddr.ID] = knownPeer
	}

	var sitSpot *KnownPeerSitSpot
findSitSpot:
	for _, oneSitSpot := range knownPeer.SitSpots {
		for maddrOld := range oneSitSpot.Addresses {
			for _, maddrNew := range peerAddr.Addrs {
				if maddrOld == maddrNew.String() {
					sitSpot = oneSitSpot
					break findSitSpot
				}
			}
		}
	}

	if sitSpot == nil {
		sitSpot = &KnownPeerSitSpot{}
		knownPeer.SitSpots = append(knownPeer.SitSpots, sitSpot)
	}

	if sitSpot.Addresses == nil {
		sitSpot.Addresses = map[string]time.Time{}
	}
	for _, maddr := range peerAddr.Addrs {
		sitSpot.Addresses[maddr.String()] = time.Now()
	}

	knownPeersJSON, err := json.Marshal(mesh.knownPeers)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(filepath.Join(mesh.cacheDir, `known_peers.json`), knownPeersJSON, 0640)
	if err != nil {
		return
	}

	return
}

func (mesh *Network) addStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() {
		mesh.logger.Debugf(`/addStream %v %v -> %v`, stream.Conn().RemotePeer(), stream.Conn().RemoteMultiaddr(), err)
		maddr := stream.Conn().RemoteMultiaddr()
		if err != nil {
			err = errors.Wrap(err)

			oldBadConnectionCount, ok := mesh.badConnectionCount.Load(maddr.String())
			var newBadConnectionCount uint64
			if !ok {
				newBadConnectionCount = 1
			} else {
				newBadConnectionCount = oldBadConnectionCount.(uint64) + 1
			}
			mesh.badConnectionCount.Store(maddr.String(), newBadConnectionCount)
			mesh.logger.Debugf("new bad-connection-count value for address %v is %v", maddr, newBadConnectionCount)
			return
		}
		mesh.badConnectionCount.Store(maddr.String(), uint64(0))
	}()

	mesh.logger.Debugf("addStream %v %v %v", stream.Protocol(), stream.Conn().RemotePeer(), stream.Conn().RemoteMultiaddr())
	if stream.Conn().RemotePeer() == mesh.ipfsNode.PeerHost.ID() {
		mesh.logger.Debugf("it's my ID, skip")
	}

	err = mesh.sendAuthData(stream)
	if err != nil {
		mesh.logger.Infof("unable to send auth data: %v", errors.Wrap(err))
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
	mesh.streamsLocker.Lock()
	defer mesh.streamsLocker.Unlock()
	oldStreamI, _ := mesh.streams.Load(stream.Conn().RemotePeer())
	if oldStreamI != nil {
		_ = oldStreamI.(Stream).Close()
	}
	mesh.streams.Store(stream.Conn().RemotePeer(), stream)

	go mesh.streamHandler(stream)

	for _, streamHandler := range mesh.streamHandlers {
		go streamHandler.ConsiderKnownPeer(peerAddr)
		go streamHandler.OnPeerConnect(peerAddr.ID)
	}

	go func() {
		err = mesh.addToKnownPeers(peerAddr)
		if err != nil {
			mesh.logger.Error(`unable to add the peer to the list of known peers: %v`, err)
		}
	}()
	return
}

func (mesh *Network) NewStream(peerID peer.ID, protocolID p2pprotocol.ID) (stream Stream, err error) {
	return mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, protocolID)
}

func (mesh *Network) ClosePeer(peerID peer.ID) {
	for _, conn := range mesh.ipfsNode.PeerHost.Network().ConnsToPeer(peerID) {
		err := conn.Close()
		if err != nil {
			mesh.logger.Error(errors.Wrap(err))
		}
	}
}

func (mesh *Network) ConnectPeer(peerID peer.ID) {
	mesh.considerPeerAddr(AddrInfo{ID: peerID})
}

func (mesh *Network) IsIncomingStream(peerID peer.ID) *bool {
	for _, conn := range mesh.ipfsNode.PeerHost.Network().ConnsToPeer(peerID) {
		for _, stream := range conn.GetStreams() {
			if stream.Protocol() == p2pProtocolID {
				return &[]bool{stream.Stat().Direction == network.DirInbound}[0]
			}
		}
	}
	return nil
}
