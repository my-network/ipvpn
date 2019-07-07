package vpn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/ed25519"

	"github.com/xaionaro-go/errors"
)

var (
	ErrInvalidSignature = errors.New(`invalid signature`)
)

type MessagePingData struct {
	SequenceID uint64
	SendTS     int64
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

	signature, err := privKey.Sign(rand.Reader, ping.MessagePingData.Bytes(), crypto.Hash(0))
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
