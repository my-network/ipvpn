package vpn

import (
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/ipvpn/network"
)

const (
	bufferSize = 1 << 20
)

type Stream = network.Stream

type VPN struct {
	logger           Logger
	myID             peer.ID
	intAlias         IntAlias
	intAliasFilePath string
	peers            sync.Map
	subnet           net.IPNet
	newStreamLocker  sync.Mutex
	buffer           [bufferSize]byte
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

func (vpn *VPN) setupIfaceIPAddress() error {
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

func (vpn *VPN) newStream(stream Stream) (err error) {
	defer func() { err = errors.Wrap(err) }()

	vpn.newStreamLocker.Lock()
	defer vpn.newStreamLocker.Unlock()

	peerID := stream.Conn().RemotePeer()
	if peerID == vpn.myID {
		panic("got a connection to myself, should not happened, ever")
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
		changeOnOurSide := false
		if vpn.intAlias.MaxNetworkSize > remoteIntAliases[0].MaxNetworkSize {
			changeOnOurSide = true
		} else if vpn.intAlias.MaxNetworkSize == remoteIntAliases[0].MaxNetworkSize {
			if vpn.intAlias.Timestamp.UnixNano() > remoteIntAliases[0].Timestamp.UnixNano() {
				changeOnOurSide = true
			} else if vpn.intAlias.Timestamp.UnixNano() == remoteIntAliases[0].Timestamp.UnixNano() {
				if vpn.myID > peerID {
					changeOnOurSide = true
				}
			}
		}

		if changeOnOurSide {
			vpn.logger.Debugf("int alias collision, remote side should change it's alias %v <= %v && %v <= %v && %v < %v",
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
		VPN:      vpn,
		Stream:   stream,
		IntAlias: *remoteIntAliases[0],
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

func (vpn *VPN) NewStream(stream Stream) {
	if err := vpn.newStream(stream); err != nil {
		vpn.logger.Error(errors.Wrap(err))
		_ = stream.Close()
	}
}
