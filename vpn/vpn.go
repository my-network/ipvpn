package vpn

import (
	e "errors"
	"github.com/agl/ed25519/extra25519"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/curve25519"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/wgcreate"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/xaionaro-go/ipvpn/network"
)

const (
	bufferSize              = 1 << 20
	ipvpnIfaceNameTunnel    = `ipvpn_tunnel`
	ipvpnIfaceNameDirect    = `ipvpn_direct`
	defaultMTU              = 1200
	ipvpnPortTunnel         = 18291
	ipvpnPortDirect         = 18292
	directConnectionTimeout = 30 * time.Second
)

var (
	secondaryKeyBase = [32]byte{'i', 'p', 'v', 'p', 'n'}
)

var (
	ErrAlreadyClosed  = e.New("already closed")
	ErrAlreadyStarted = e.New("already started")
)

type Stream = network.Stream
type AddrInfo = network.AddrInfo

type VPN struct {
	logger               Logger
	myID                 peer.ID
	intAlias             IntAlias
	intAliasFilePath     string
	peers                sync.Map
	subnet               net.IPNet
	newStreamLocker      sync.Mutex
	buffer               [bufferSize]byte
	wgctl                *wgctrl.Client
	privKey              ed25519.PrivateKey
	psk                  []byte
	ifaceNameTunnel      string
	ifaceNameDirect      string
	state                uint32
	currentPrimaryIP     net.IP
	wgListenerTunnelAddr net.UDPAddr
	wgListenerDirectAddr net.UDPAddr
}

func New(intAliasFilePath string, subnet net.IPNet, logger Logger) (vpn *VPN, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err)
			vpn = nil
		}
	}()

	vpn = &VPN{
		logger:           logger,
		subnet:           subnet,
		intAliasFilePath: intAliasFilePath,
		ifaceNameTunnel:  ipvpnIfaceNameTunnel,
		ifaceNameDirect:  ipvpnIfaceNameDirect,
	}

	vpn.wgctl, err = wgctrl.New()
	if err != nil {
		return
	}

	intAliasFileData, readErr := ioutil.ReadFile(intAliasFilePath)
	if readErr == nil {
		err = vpn.intAlias.Unmarshal(intAliasFileData)
		if err != nil {
			return
		}
		if vpn.intAlias.Timestamp.UnixNano() < time.Date(2019, 06, 23, 19, 47, 29, 0, time.UTC).UnixNano() { // if the computer has a broken battery and the clock shows wrong value
			vpn.intAlias.Timestamp = time.Now()
		}
	} else {
		vpn.intAlias.Value = 1
		vpn.intAlias.Timestamp = time.Now()
		vpn.intAlias.MaxNetworkSize = 1
		err = vpn.UpdateIntAliasMetadataAndSave()
		if err != nil {
			return
		}
	}

	return
}

func (vpn *VPN) GetNetworkMaximalSize() uint64 {
	addressLength := net.IPv6len * 8
	_, bits := vpn.subnet.Mask.Size()
	if vpn.subnet.IP.To4() != nil {
		addressLength = net.IPv4len * 8
	}
	return (1 << uint(addressLength-bits)) - 3
}

func (vpn *VPN) SetID(newID peer.ID) {
	vpn.myID = newID
	vpn.intAlias.PeerID = vpn.myID
	err := vpn.UpdateIntAliasMetadataAndSave()
	if err != nil {
		vpn.logger.Error(errors.Wrap(err))
	}
}

func (vpn *VPN) setPrivateKey(privKey ed25519.PrivateKey) {
	vpn.privKey = privKey
}

func (vpn *VPN) GetIP(intAlias uint64, isSecondary bool) (resultIP net.IP, err error) {
	defer func() { err = errors.Wrap(err) }()
	defer func() { vpn.logger.Debugf("GetIP(%v, %v) -> %v, %v", intAlias, isSecondary, resultIP, err) }()

	maskOnes, maskBits := vpn.subnet.Mask.Size()
	if vpn.intAlias.Value >= 1<<uint32(maskBits-maskOnes-1) {
		return nil, errors.New("int alias value is too big or subnet is too small")
	}

	resultIP = make(net.IP, len(vpn.subnet.IP))
	copy(resultIP, vpn.subnet.IP)
	if resultIP.To4() == nil {
		return nil, errors.New("IPv6 support is not implemented, yet")
	}

	octet := len(resultIP) - 1

	offset := intAlias
	if isSecondary {
		offset += 1 << uint32(maskBits-maskOnes-1)
	}
	for offset > 0 && octet >= 0 {
		localOffset := uint8(offset % 256)
		offset /= 256
		if uint16(resultIP[octet])+uint16(localOffset) >= 256 {
			offset++
		}
		resultIP[octet] += localOffset
		octet--
	}

	return resultIP, nil
}

func (vpn *VPN) IsBadAddress(maddr multiaddr.Multiaddr) bool {
	addr4, err := maddr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return false
	}
	return vpn.subnet.Contains(net.ParseIP(addr4))
}

func (vpn *VPN) GetMyIP(isSecondary bool) (net.IP, error) {
	return vpn.GetIP(vpn.intAlias.Value, isSecondary)
}

func (vpn *VPN) getPeers() (peers Peers) {
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		peers = append(peers, peer)
		return true
	})

	return
}

func (vpn *VPN) IsStarted() bool {
	return atomic.LoadUint32(&vpn.state) == 1
}

func (vpn *VPN) Start() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !atomic.CompareAndSwapUint32(&vpn.state, 0, 1) {
		return ErrAlreadyStarted
	}

	vpn.ifaceNameTunnel, err = wgcreate.Create(vpn.ifaceNameTunnel, defaultMTU, true, &device.Logger{
		Debug: log.New(vpn.logger.GetDebugWriter(), "[wireguard-tunnel] ", 0),
		Info:  log.New(vpn.logger.GetInfoWriter(), "[wireguard-tunnel] ", 0),
		Error: log.New(vpn.logger.GetErrorWriter(), "[wireguard-tunnel] ", 0),
	})
	if err != nil {
		return
	}

	vpn.ifaceNameDirect, err = wgcreate.Create(vpn.ifaceNameDirect, defaultMTU, true, &device.Logger{
		Debug: log.New(vpn.logger.GetDebugWriter(), "[wireguard-direct] ", 0),
		Info:  log.New(vpn.logger.GetInfoWriter(), "[wireguard-direct] ", 0),
		Error: log.New(vpn.logger.GetErrorWriter(), "[wireguard-direct] ", 0),
	})
	if err != nil {
		return
	}

	err = vpn.updateWireGuardConfiguration()
	if err != nil {
		_ = vpn.deleteLink()
		return
	}

	err = vpn.startFallbackConnector()
	if err != nil {
		_ = vpn.deleteLink()
		return
	}

	return
}

func (vpn *VPN) fallbackConnectorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for vpn.IsStarted() {
		select {
		case <-ticker.C:
		}

		m := map[string]*wgtypes.Peer{}

		{ // scanning tunneled peers
			dev, err := vpn.wgctl.Device(vpn.ifaceNameTunnel)
			if err != nil {
				return
			}

			for idx, wgPeer := range dev.Peers {
				m[wgPeer.Endpoint.String()] = &dev.Peers[idx]
			}
		}

		{ // scanning direct peers
			dev, err := vpn.wgctl.Device(vpn.ifaceNameDirect)
			if err != nil {
				return
			}

			for idx, wgPeer := range dev.Peers {
				m[wgPeer.Endpoint.String()] = &dev.Peers[idx]
			}
		}

		for _, vpnPeer := range vpn.getPeers() {
			wgPeerTunnel := m[vpnPeer.TunnelAddr.String()]
			if wgPeerTunnel == nil {
				vpn.logger.Debugf("WG peer (via IPFS) is closed %v %v. Closing VPN peer.", vpnPeer.IntAlias.Value, vpnPeer.GetID())
				err := vpnPeer.Close()
				if err != nil {
					vpn.logger.Error(errors.Wrap(err))
				}
				continue
			}
			wgPeerDirect := m[vpnPeer.DirectAddr.String()]
			if wgPeerDirect == nil {
				vpn.logger.Debugf("WG peer (direct) is not opened. %v %v", vpnPeer.IntAlias.Value, vpnPeer.GetID())
				continue
			}
			var err error
			if time.Since(wgPeerDirect.LastHandshakeTime).Nanoseconds() < directConnectionTimeout.Nanoseconds() {
				err = vpnPeer.switchChannel(channelTypeDirect)
			} else {
				err = vpnPeer.switchChannel(channelTypeIPFS)
			}
			if err != nil {
				vpn.logger.Error(errors.Wrap(err))
			}
		}
	}
}

func (vpn *VPN) startFallbackConnector() (err error) {
	defer func() { err = errors.Wrap(err) }()

	go vpn.fallbackConnectorLoop()

	return
}

func (vpn *VPN) deleteLink() (err error) {
	defer func() { err = errors.Wrap(err) }()

	// TODO: implement it

	return
}

func (vpn *VPN) Close() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !atomic.CompareAndSwapUint32(&vpn.state, 1, 0) {
		return ErrAlreadyClosed
	}

	err = vpn.wgctl.Close()
	if err != nil {
		return
	}

	err = vpn.deleteLink()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) updateWireGuardConfiguration() (err error) {
	defer func() { err = errors.Wrap(err) }()

	if !vpn.IsStarted() {
		return
	}

	peersCfgTunnel, err := vpn.getPeers().toWireGuardTunnelConfigs()
	if err != nil {
		return
	}

	cfgTunnel := wgtypes.Config{
		PrivateKey:   &wgtypes.Key{},
		ListenPort:   &[]int{ipvpnPortTunnel}[0],
		FirewallMark: &[]int{1}[0],
		Peers:        peersCfgTunnel,
		ReplacePeers: true,
	}

	vpn.wgListenerTunnelAddr.IP = net.ParseIP(`127.0.0.1`)
	vpn.wgListenerTunnelAddr.Port = ipvpnPortTunnel

	// WireGuard uses Curve25519, while IPFS uses ED25519. So we need to convert it:
	{
		var privKey [64]byte
		copy(privKey[:], vpn.privKey)
		extra25519.PrivateKeyToCurve25519((*[32]byte)(cfgTunnel.PrivateKey), &privKey)
	}

	vpn.logger.Debugf("wgConfigTunnel: %v", cfgTunnel)
	vpn.logger.Debugf("wgConfigTunnel public key: %v", cfgTunnel.PrivateKey.PublicKey())

	err = vpn.wgctl.ConfigureDevice(vpn.ifaceNameTunnel, cfgTunnel)
	if err != nil {
		return
	}

	peersCfgDirect, err := vpn.getPeers().toWireGuardDirectConfigs()
	if err != nil {
		return
	}

	cfgDirect := wgtypes.Config{
		PrivateKey:   &wgtypes.Key{},
		ListenPort:   &[]int{ipvpnPortDirect}[0],
		FirewallMark: &[]int{1}[0],
		Peers:        peersCfgDirect,
		ReplacePeers: true,
	}

	vpn.wgListenerDirectAddr.IP = net.ParseIP(`0.0.0.0`)
	vpn.wgListenerDirectAddr.Port = ipvpnPortDirect

	/*
		// WireGuard doesn't support multiple endpoints for one peer, so we do a separate WireGuard
		// listener for the direct endpoints with another key (shifted on a constant value)
		wgPrivateKeyDirect := shiftWgKey(cfgTunnel.PrivateKey)
		copy(cfgDirect.PrivateKey[:], wgPrivateKeyDirect[:])*/

	// We separated WG interfaces, so there's no need to separate keys anymore
	copy(cfgDirect.PrivateKey[:], cfgTunnel.PrivateKey[:])

	vpn.logger.Debugf("wgConfigDirect: %v", cfgDirect)
	vpn.logger.Debugf("wgConfigDirect public key: %v", cfgDirect.PrivateKey.PublicKey())

	err = vpn.wgctl.ConfigureDevice(vpn.ifaceNameDirect, cfgDirect)
	if err != nil {
		return
	}

	err = vpn.setupIfaceIPAddress()
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) SetPrivateKey(privKey ed25519.PrivateKey) {
	vpn.setPrivateKey(privKey)
	err := vpn.updateWireGuardConfiguration()
	if err != nil {
		vpn.logger.Error("unable to configure VPN", err)
	}
}

func (vpn *VPN) setPSK(psk []byte) {
	vpn.psk = psk
}

func (vpn *VPN) SetPSK(psk []byte) {
	vpn.setPSK(psk)
	err := vpn.updateWireGuardConfiguration()
	if err != nil {
		vpn.logger.Error("unable to configure VPN", err)
	}
}

func (vpn *VPN) GetPSK() []byte {
	return vpn.psk
}

func (vpn *VPN) sendIntAliases(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	knownAliases := IntAliases{vpn.intAlias.Copy()}
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		knownAliases = append(knownAliases, peer.IntAlias.Copy())
		return true
	})
	for _, intAlias := range knownAliases {
		intAlias.Since = time.Since(intAlias.Timestamp)
		intAlias.Timestamp = time.Time{}
	}
	b, err := knownAliases.Marshal()
	if err != nil {
		return
	}

	n, err := stream.Write(b)
	vpn.logger.Debugf("sendIntAlias(): stream.Write(): %v %v %v", n, err, string(b))
	if err != nil {
		return
	}

	return
}

func (vpn *VPN) recvIntAliases(stream Stream) (remoteIntAliases IntAliases, err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("recvIntAlias(): stream.Read()...")
	n, err := stream.Read(vpn.buffer[:])
	vpn.logger.Debugf("recvIntAlias(): stream.Read(): %v %v %v", n, err, string(vpn.buffer[:n]))

	if n >= bufferSize {
		return nil, errors.New("too big message")
	}
	if err != nil {
		return
	}

	err = remoteIntAliases.Unmarshal(vpn.buffer[:n])
	if err != nil {
		return
	}

	if len(remoteIntAliases) == 0 {
		return nil, errors.New("empty slice")
	}

	return
}

func (vpn *VPN) setupIfaceIPAddress() (err error) {
	defer func() { err = errors.Wrap(err) }()

	myPrimaryIP, err := vpn.GetMyIP(false)
	if err != nil {
		return
	}

	if vpn.currentPrimaryIP.String() == myPrimaryIP.String() {
		return
	}

	mySecondaryIP, err := vpn.GetMyIP(true)
	if err != nil {
		return
	}

	vpn.currentPrimaryIP = myPrimaryIP

	err = wgcreate.ResetIPs(vpn.ifaceNameTunnel)
	if err != nil {
		return
	}

	err = wgcreate.ResetIPs(vpn.ifaceNameDirect)
	if err != nil {
		return
	}

	maskOnes, maskBits := vpn.subnet.Mask.Size()

	tunnelSubnet := vpn.subnet
	tunnelSubnet.Mask = net.CIDRMask(maskOnes+1, maskBits)
	err = wgcreate.AddIP(vpn.ifaceNameTunnel, myPrimaryIP, tunnelSubnet)
	if err != nil {
		return
	}

	directSubnet := vpn.subnet
	directSubnet.Mask = net.CIDRMask(maskOnes+1, maskBits)
	directSubnet.IP, err = vpn.GetIP(0, true)
	if err != nil {
		return
	}
	err = wgcreate.AddIP(vpn.ifaceNameDirect, mySecondaryIP, directSubnet)
	if err != nil {
		return
	}

	return nil
}

func (vpn *VPN) SetIntAlias(newValue uint64) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("SetIntAlias: %v->%v", vpn.intAlias.Value, newValue)

	vpn.intAlias.Value = newValue
	vpn.intAlias.Timestamp = time.Now()

	return vpn.setupIfaceIPAddress()
}

func (vpn *VPN) GetNetworkSize() (result uint64) {
	result = 1 // myself is already "1"

	vpn.peers.Range(func(_, _ interface{}) bool {
		result++
		return true
	})

	return
}

func (vpn *VPN) UpdateIntAliasMetadataAndSave() (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.logger.Debugf("saving the int alias %v to %v", vpn.intAlias, vpn.intAliasFilePath)

	curNetworkSize := vpn.GetNetworkSize()
	if curNetworkSize > vpn.intAlias.MaxNetworkSize {
		vpn.intAlias.MaxNetworkSize = curNetworkSize
	}
	vpn.intAlias.Timestamp = time.Now()
	b, err := vpn.intAlias.Marshal()
	if err != nil {
		return
	}

	err = ioutil.WriteFile(vpn.intAliasFilePath+"-new", b, 0644)
	if err != nil {
		return
	}

	_ = os.Remove(vpn.intAliasFilePath)

	err = os.Rename(vpn.intAliasFilePath+"-new", vpn.intAliasFilePath)
	if err != nil {
		return
	}

	return
}

// WireGuard uses Curve25519, while IPFS uses ED25519. So we need to convert it:
func streamToWgPubKey(stream Stream) (result wgtypes.Key, err error) {
	defer func() { err = errors.Wrap(err) }()

	var pubKey [32]byte
	pubKeyBytes, err := stream.Conn().RemotePublicKey().Raw()
	if err != nil {
		return
	}
	copy(pubKey[:], pubKeyBytes)
	extra25519.PublicKeyToCurve25519((*[32]byte)(&result), &pubKey)
	return
}

func shiftWgKey(in *wgtypes.Key) (out wgtypes.Key) {
	curve25519.ScalarMult((*[32]byte)(&out), (*[32]byte)(in), &secondaryKeyBase)
	return
}

func (vpn *VPN) newStream(stream Stream, peerAddr AddrInfo) (err error) {
	defer func() { err = errors.Wrap(err) }()

	wgPubKeyTunnel, err := streamToWgPubKey(stream)
	if err != nil {
		return
	}
	vpn.logger.Debugf("new stream %v, pubkey %v", peerAddr.ID, wgPubKeyTunnel)

	/*
		// WireGuard doesn't support multiple endpoints for one peer, so we do a separate WireGuard
		// peer for the direct endpoint
		wgPubKeyDirect := shiftWgKey(&wgPubKeyTunnel)
	*/
	// We've separated WG interfaces, so there's no need to separate keys anymore
	wgPubKeyDirect := wgPubKeyTunnel

	vpn.newStreamLocker.Lock()
	defer vpn.newStreamLocker.Unlock()

	peerID := stream.Conn().RemotePeer()
	if peerID == vpn.myID {
		return errors.New("got a connection to myself, should not happened, ever")
	}
	err = vpn.sendIntAliases(stream)
	if err != nil {
		return
	}
	remoteIntAliases, err := vpn.recvIntAliases(stream)
	if err != nil {
		return
	}
	notMyIntAliases := map[uint64]*IntAlias{}
	vpn.peers.Range(func(_, peerI interface{}) bool {
		peer := peerI.(*Peer)
		notMyIntAliases[peer.IntAlias.Value] = &peer.IntAlias
		return true
	})
	for _, remoteIntAlias := range remoteIntAliases {
		if remoteIntAlias.PeerID == vpn.intAlias.PeerID {
			continue
		}
		remoteIntAlias.Timestamp = time.Now().Add(-remoteIntAlias.Since)
		notMyIntAliases[remoteIntAlias.Value] = remoteIntAlias
	}
	if remoteIntAliases[0].Value == vpn.intAlias.Value {
		changeOnRemoteSide := false
		if vpn.intAlias.MaxNetworkSize > remoteIntAliases[0].MaxNetworkSize {
			changeOnRemoteSide = true
		} else if vpn.intAlias.MaxNetworkSize == remoteIntAliases[0].MaxNetworkSize {
			if vpn.intAlias.Timestamp.UnixNano() > remoteIntAliases[0].Timestamp.UnixNano() {
				changeOnRemoteSide = true
			} else if vpn.intAlias.Timestamp.UnixNano() == remoteIntAliases[0].Timestamp.UnixNano() {
				if vpn.myID < peerID {
					changeOnRemoteSide = true
				}
			}
		}

		if changeOnRemoteSide {
			vpn.logger.Debugf("int alias collision, remote side should change it's alias %v <?= %v , %v <?= %v, %v >? %v",
				vpn.intAlias.Value, remoteIntAliases[0].Value,
				vpn.intAlias.Timestamp, remoteIntAliases[0].Timestamp,
				vpn.myID, peerID)

			err = vpn.sendIntAliases(stream)
			if err != nil {
				return
			}
			remoteIntAliases, err = vpn.recvIntAliases(stream)
			if err != nil {
				return
			}
			if remoteIntAliases[0].Value == vpn.intAlias.Value {
				return errors.New("remote side decided not to change it's int alias, close connection")
			}
		} else {
			vpn.logger.Debugf("int alias collision, changing our int alias")
			networkSize := vpn.GetNetworkMaximalSize()
			for i := uint64(1); i < networkSize; i++ {
				if notMyIntAliases[i] == nil {
					err = vpn.SetIntAlias(i)
					if err != nil {
						return
					}
					break
				}
			}
			err = vpn.sendIntAliases(stream)
			if err != nil {
				return
			}
			_, err = vpn.recvIntAliases(stream)
			if err != nil {
				return
			}
		}
	}

	if oldPeerI, _ := vpn.peers.Load(peerID); oldPeerI != nil {
		oldPeer := oldPeerI.(*Peer)
		_ = oldPeer.Close()
	}

	remoteIntAliases[0].Timestamp = time.Now().Add(-remoteIntAliases[0].Since)
	newPeer := &Peer{
		VPN:            vpn,
		Stream:         stream,
		AddrInfo:       peerAddr,
		IntAlias:       *remoteIntAliases[0],
		WgPubKeyTunnel: wgPubKeyTunnel,
		WgPubKeyDirect: wgPubKeyDirect,
	}

	err = newPeer.Start()
	if err != nil {
		return
	}

	vpn.peers.Store(peerID, newPeer)

	saveErr := vpn.UpdateIntAliasMetadataAndSave()
	if saveErr != nil {
		vpn.logger.Error(saveErr)
	}

	return
}

func (vpn *VPN) NewStream(stream Stream, peerAddr AddrInfo) {
	if err := vpn.newStream(stream, peerAddr); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		err := stream.Close()
		if err != nil {
			vpn.logger.Error(errors.Wrap(err))
			return
		}
	}
}
