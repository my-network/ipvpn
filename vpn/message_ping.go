package vpn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

var (
	ErrInvalidSignature = errors.New(`invalid signature`)
)

type MessagePingData struct {
	SequenceID uint64
	SendTS     time.Time
}

type MessagePing struct {
	MessagePingData
	SenderSignature [ed25519.SignatureSize]byte
}

func (pingData *MessagePingData) Bytes() []byte {
	result := make([]byte, binary.Size(pingData))
	err := binary.Write(bytes.NewBuffer(result), binary.LittleEndian, pingData)
	if err != nil {
		panic(err)
	}
	return result
}

func (ping *MessagePing) SignSender(privKey ed25519.PrivateKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	signature, err := privKey.Sign(rand.Reader, ping.MessagePingData.Bytes(), nil)
	if err != nil {
		return
	}
	copy(ping.SenderSignature[:], signature)
	return
}

func (ping *MessagePing) VerifySender(pubKey ed25519.PublicKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	isValidSignature := ed25519.Verify(pubKey, ping.SenderSignature[:], ping.MessagePingData.Bytes())
	if !isValidSignature {
		return ErrInvalidSignature
	}
	return
}

func (ping *MessagePing) Bytes() []byte {
	result := make([]byte, binary.Size(ping))
	err := binary.Write(bytes.NewBuffer(result), binary.LittleEndian, ping)
	if err != nil {
		panic(err)
	}
	return result
}

func (ping *MessagePing) Read(b []byte) error {
	if len(b) != binary.Size(ping) {
		return errors.Wrap(ErrInvalidSize, len(b), binary.Size(ping))
	}

	return errors.Wrap(binary.Read(bytes.NewReader(b), binary.LittleEndian, ping))
}
