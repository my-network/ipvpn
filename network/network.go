package network

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"math"
	"net"
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
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"github.com/xaionaro-go/errors"
)

const (
	p2pProtocolID  = p2pprotocol.ID(`/p2p/github.com/xaionaro-go/ipvpn`)
	ipvpnMagic     = "\000\314\326This is an InterPlanetary Virtual Private Network node"
	ipfsPortString = "24001"
)

type Network struct {
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
			"/ip4/0.0.0.0/udp/" + ipfsPortString,
			"/ip6/::/tcp/" + ipfsPortString,
			"/ip6/::/udp/" + ipfsPortString,
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

	if data.AddrInfo.Addrs[0].String() != stream.Conn().RemoteMultiaddr().String() {
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
			mesh.logger.Debugf("found peer: %v", peerID)

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
			addrInfo, err := mesh.ipfsNode.Routing.FindPeer(mesh.ipfsContext, peerID)
			if err != nil {
				mesh.logger.Infof("unable to find a route to peer %v: %v", peerID, err)
				continue
			}

			stream, err := mesh.ipfsNode.PeerHost.NewStream(mesh.ipfsContext, peerID, p2pProtocolID)
			if err != nil {
				mesh.logger.Infof("unable to connect to peer %v: %v", peerID, err)
				continue
			}

			stream = mesh.tryConnectByOptimalPath(stream, &addrInfo, false)
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
			err = mesh.addStream(stream, addrInfo)
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

func (mesh *Network) addToBootstrapPeers(maddr p2pcore.Multiaddr, peerID peer.ID) (err error) {
	defer func() {
		err = errors.Wrap(err)
	}()

	cfg, err := mesh.ipfsNode.Repo.Config()
	if err != nil {
		return
	}

	peerString := maddr.String() + `/ipfs/` + peerID.String()

	found := false
	for _, bootstrapPeer := range cfg.Bootstrap {
		if bootstrapPeer == peerString {
			found = true
			break
		}
	}

	if !found {
		cfg.Bootstrap = append(cfg.Bootstrap, peerString)
	}

	err = mesh.saveIPFSRepositoryConfig(cfg)
	if err != nil {
		return err
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
	}

	{ // Add the node to bootstrap nodes
		maddr := stream.Conn().RemoteMultiaddr()
		portStr, err := maddr.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			portStr, err = maddr.ValueForProtocol(multiaddr.P_UDP)
		}
		if err != nil {
			mesh.logger.Debugf("unable to get TCP/UDP port of multiaddr %v: %v", maddr, err)
		} else {
			if portStr == ipfsPortString {
				err := mesh.addToBootstrapPeers(maddr, peerAddr.ID)
				if err != nil {
					mesh.logger.Error("Unable to add %v to the list of bootstrap nodes: %v", maddr, errors.Wrap(err))
				}
			}
		}
	}

	return
}
