package network

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
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
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"github.com/xaionaro-go/errors"
)

const (
	p2pProtocolID  = p2pprotocol.ID(`/p2p/github.com/my-network/ipvpn`)
	ipvpnMagic     = "\000\314\326This is an InterPlanetary Virtual Private Network node"
	ipfsPortString = "24001"
)

const (
	sitSpotsPerPeerLimit = 16
)

var (
	sitSpotExpireInterval = time.Hour * 24 * 30
)

type Network struct {
	cacheDir                   string
	logger                     Logger
	networkName                string
	publicSharedKeyword        []byte
	privateSharedKeyword       []byte
	ipfsNode                   *core.IpfsNode
	ipfsContext                context.Context
	ipfsContextCancelFunc      func()
	streams                    sync.Map
	streamHandlers             []StreamHandler
	callPathOptimizerCount     sync.Map
	badConnectionCount         sync.Map
	forbidOutcomingConnections sync.Map
	knownPeers                 KnownPeers
	knownPeersLocker           sync.RWMutex
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
			"/ip4/0.0.0.0/tcp/" + ipfsPortString,
			"/ip4/0.0.0.0/udp/" + ipfsPortString + "/quic",
			"/ip6/::/tcp/" + ipfsPortString,
			"/ip6/::/udp/" + ipfsPortString + "/quic",
			// Also we need ICMP :(
		},
		Announce:   []string{},
		NoAnnounce: []string{},
		API:        ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/25001"},
		Gateway:    ipfsConfig.Strings{"/ip4/127.0.0.1/tcp/28080"},
	}
}

func initRepo(logger Logger, repoPath string, agreeToBeRelay bool) (err error) {
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
			EnableAutoNATService: true,
			EnableAutoRelay:      true, // see https://github.com/ipfs/go-ipfs/blob/master/docs/config.md
			EnableRelayHop:       agreeToBeRelay,
		},
		Experimental: ipfsConfig.Experiments{
			// https://github.com/ipfs/go-ipfs/blob/master/docs/experimental-features.md

			FilestoreEnabled: true,
			QUIC:             true,
		},
	})
	if err != nil {
		return
	}

	return
}

type VPN interface {
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

	var knownPeers KnownPeers
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

	if ipfsRepoConfig.Swarm.EnableRelayHop != agreeToBeRelay {
		logger.Debugf(`fixing and saving the repository's config: agreeToBeRelay`)

		ipfsRepoConfig.Swarm.EnableRelayHop = agreeToBeRelay
		err = ipfsRepo.SetConfig(ipfsRepoConfig)
		if err != nil {
			logger.Error("unable to save new repo config: %v", err)
		}
	}

	if len(knownPeers) > 0 {
		logger.Debugf(`fixing the repository's config: adding known peers' (count: %v) addresses to bootstrap nodes`, len(knownPeers))

		for _, knownPeer := range knownPeers {
			sitSpots := knownPeer.SitSpots
			if len(sitSpots) > sitSpotsPerPeerLimit {
				sitSpots = sitSpots[:sitSpotsPerPeerLimit]
			}
			for _, sitSpot := range sitSpots {
				if time.Since(sitSpot.LastSuccessfulHandshakeTS) > sitSpotExpireInterval {
					// We actually could put "break" here instead of "continue", because sitSpots are already
					// sorted by LastSuccessfulHandshakeTS. But performance is not important here, so we
					// leave a "continue" here just in case.
					continue
				}
				for _, maddr := range sitSpot.Addresses {
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
		return
	}

	mesh = &Network{
		cacheDir:              cacheDir,
		logger:                logger,
		networkName:           networkName,
		publicSharedKeyword:   generatePublicSharedKeyword(networkName, psk),
		privateSharedKeyword:  generatePrivateSharedKeyword(networkName, psk),
		ipfsNode:              ipfsNode,
		ipfsContext:           ctx,
		ipfsContextCancelFunc: cancelFunc,
		streamHandlers:        streamHandlers,
		knownPeers:            knownPeers,
	}

	err = mesh.start()
	if err != nil {
		_ = mesh.Close()
		return
	}

	return
}

type addrInfoWithLatencies struct {
	BadConnectionCount []uint64
	Latencies          []time.Duration
	AddrInfo           *AddrInfo
}

func (data *addrInfoWithLatencies) Len() int { return len(data.AddrInfo.Addrs) }
func (data *addrInfoWithLatencies) Less(i, j int) bool {
	if data.BadConnectionCount[i] != data.BadConnectionCount[j] {
		return data.BadConnectionCount[i] < data.BadConnectionCount[j]
	}
	return data.Latencies[i] < data.Latencies[j]
}
func (data *addrInfoWithLatencies) Swap(i, j int) {
	data.BadConnectionCount[i], data.BadConnectionCount[j] = data.BadConnectionCount[j], data.BadConnectionCount[i]
	data.Latencies[i], data.Latencies[j] = data.Latencies[j], data.Latencies[i]
	data.AddrInfo.Addrs[i], data.AddrInfo.Addrs[j] = data.AddrInfo.Addrs[j], data.AddrInfo.Addrs[i]
}

func (mesh *Network) tryConnectByOptimalPath(stream Stream, addrInfo *AddrInfo, isIncoming bool) Stream {
	// Init data
	data := addrInfoWithLatencies{
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
	measureLatencyContext, _ := context.WithTimeout(context.Background(), time.Second)
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

	if data.AddrInfo.Addrs[0].String() != stream.Conn().RemoteMultiaddr().String() && (isIncoming && strings.HasSuffix(stream.Conn().RemoteMultiaddr().String(), `/quic`)) {
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

		stream, err = mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, addrInfo.ID, p2pProtocolID)
		if err != nil {
			mesh.logger.Debugf("unable create a new stream to %v: %v", addrInfo.ID, errors.Wrap(err))
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
			mesh.logger.Infof("their latency is higher, not complying", latency, data.Latencies[0])
			return stream
		}
		_ = stream.Close()
		return nil
	}

	return stream
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
			peerID := peerAddr.ID
			mesh.logger.Debugf("found peer: %v: %v", peerID, peerAddr.Addrs)

			if peerID == mesh.ipfsNode.PeerHost.ID() {
				mesh.logger.Debugf("my ID, skip")
				continue
			}

			/*if t, ok := mesh.forbidOutcomingConnections.Load(peerID); ok {
				until := t.(time.Time)
				if until.After(time.Now()) {
					mesh.logger.Debugf("we promised not to try to connect to this node: %v", peerID)
					continue
				}
				mesh.forbidOutcomingConnections.Delete(peerID)
			}*/

			if peerAddr.ID == "" {
				hours := (1 << count) - 1
				mesh.logger.Debugf("empty peer ID, sleep %v hours and restart FindProvidersAsync", hours)
				time.Sleep(time.Hour * time.Duration(hours))
				provChan = mesh.ipfsNode.DHT.FindProvidersAsync(mesh.ipfsContext, ipfsCid, 1<<16)
				count++
				continue
			}

			if len(peerAddr.Addrs) == 0 {
				mesh.logger.Debugf("mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerID)...")
				var err error
				peerAddr, err = mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerID)
				if err != nil {
					mesh.logger.Infof("unable to find a route to peer %v: %v", peerID, err)
					continue
				}
				mesh.logger.Debugf("peer's addresses: %v", peerAddr.Addrs)
			}

			mesh.logger.Debugf("mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, p2pProtocolID)...")
			stream, err := mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, p2pProtocolID)
			if err != nil {
				mesh.logger.Infof("unable to connect to peer %v: %v", peerID, err)
				continue
			}
			mesh.logger.Debugf("new stream: %v", stream.Conn().RemoteMultiaddr())

			stream = mesh.tryConnectByOptimalPath(stream, &peerAddr, false)
			if stream == nil {
				mesh.logger.Debugf("no opened stream, skip")
				continue
			}

			/*shouldContinue, alreadyOptimal := mesh.tryConnectByOptimalPath(stream, &addrInfo, false)
			if !shouldContinue {
				mesh.logger.Debugf("no more tries to connect to %v", peerID)
				mesh.forbidOutcomingConnections.Store(peerID, time.Now().Add(5 * time.Minute))
				continue
			}
			if !alreadyOptimal {
				stream, err = mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, p2pProtocolID)
				if err != nil {
					mesh.logger.Infof("unable to connect to peer %v: %v", peerID, err)
					continue
				}
			}*/
			err = mesh.addStream(stream, peerAddr)
			if err != nil {
				mesh.logger.Debugf("got error from addStream(): %v", err)
				continue
			}
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

	go mesh.connector(ipfsCid)

	go func() {
		mesh.logger.Infof(`Notifying streamHandlers (such as VPN handler) about previously known peers (count == %v)`, len(mesh.knownPeers))
		mesh.knownPeersLocker.RLock()
		defer mesh.knownPeersLocker.RUnlock()

		for _, knownPeer := range mesh.knownPeers {
			var addresses []multiaddr.Multiaddr
			for _, sitSpot := range knownPeer.SitSpots {
				if time.Since(sitSpot.LastSuccessfulHandshakeTS) > sitSpotExpireInterval {
					continue
				}
				addresses = append(addresses, sitSpot.Addresses...)
			}
			for _, streamHandler := range mesh.streamHandlers {
				streamHandler.ConsiderKnownPeer(AddrInfo{ID: knownPeer.ID, Addrs: addresses})
			}
		}
	}()

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

func (mesh *Network) saveIPFSRepositoryConfig(cfg *ipfsConfig.Config) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	err = mesh.ipfsNode.Repo.SetConfig(cfg)
	if err != nil {
		return
	}

	return
}

func (mesh *Network) addToKnownPeers(peerAddr AddrInfo) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	mesh.knownPeersLocker.Lock()
	defer mesh.knownPeersLocker.Unlock()

	knownPeer := mesh.knownPeers[peerAddr.ID]
	if knownPeer == nil {
		knownPeer = &KnownPeer{ID: peerAddr.ID}
		mesh.knownPeers[peerAddr.ID] = knownPeer
	}

	var sitSpot *KnownPeerSitSpot
findSitSpot:
	for _, oneSitSpot := range knownPeer.SitSpots {
		for _, maddrOld := range oneSitSpot.Addresses {
			for _, maddrNew := range peerAddr.Addrs {
				if maddrOld.String() == maddrNew.String() {
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

	sitSpot.Addresses = peerAddr.Addrs
	sitSpot.LastSuccessfulHandshakeTS = time.Now()

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
		maddr := stream.Conn().RemoteMultiaddr()
		if err != nil {
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

	mesh.logger.Debugf("addStream %v %v", stream.Conn().RemotePeer(), stream.Conn().RemoteMultiaddr())
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
	mesh.streams.Store(stream.Conn().RemotePeer(), stream)

	for _, streamHandler := range mesh.streamHandlers {
		streamHandler.NewStream(stream, peerAddr)
		streamHandler.ConsiderKnownPeer(peerAddr)
	}

	go func() {
		err = mesh.addToKnownPeers(peerAddr)
		if err != nil {
			mesh.logger.Error(`unable to add the peer to the list of known peers: %v`, err)
		}
	}()
	return
}
