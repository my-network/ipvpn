package vpn

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/xaionaro-go/bytesextra"
	"github.com/xaionaro-go/errors"
)

const (
	PeerIDSize = 52
)

var (
	sizeOfMessageIntAlias = binary.Size(MessageIntAlias{})
)

type MessageIntAlias struct {
	PeerID         [PeerIDSize]byte
	Value          uint64
	MaxNetworkSize uint64
	Timestamp      int64
	Since          int64

	Index int32
	Count int32
}

func (msg *MessageIntAlias) FillFrom(intAlias *IntAlias) (err error) {
	defer func() { err = errors.Wrap(err) }()

	if len(intAlias.PeerID) != PeerIDSize {
		return errors.Wrap(ErrInvalidPeerID, len(intAlias.PeerID))
	}

	copy(msg.PeerID[:], []byte(intAlias.PeerID))
	msg.Value = intAlias.Value
	msg.MaxNetworkSize = intAlias.MaxNetworkSize
	msg.Timestamp = intAlias.Timestamp.UnixNano()
	msg.Since = int64(intAlias.Since)

	return
}

func (msg *MessageIntAlias) FillTo(intAlias *IntAlias) (err error) {
	defer func() { err = errors.Wrap(err) }()

	intAlias.PeerID = peer.ID(string(msg.PeerID[:]))
	intAlias.Value = msg.Value
	intAlias.MaxNetworkSize = msg.MaxNetworkSize
	intAlias.Timestamp = time.Unix(0, msg.Timestamp)
	intAlias.Since = time.Duration(msg.Since)

	return
}

func (msg *MessageIntAlias) Read(b []byte) error {
	if len(b) != sizeOfMessageIntAlias {
		return errors.Wrap(ErrInvalidSize, len(b), sizeOfMessageIntAlias)
	}

	return errors.Wrap(binary.Read(bytes.NewReader(b), binary.LittleEndian, msg))
}

func (msg *MessageIntAlias) Write(b []byte) error {
	return msg.WriteTo(bytesextra.NewWriter(b))
}

func (msg *MessageIntAlias) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, msg)
}
