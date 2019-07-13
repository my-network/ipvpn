package vpn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/ed25519"
	"io"

	"github.com/xaionaro-go/errors"
)

var (
	ErrInvalidSignature = errors.New(`invalid signature`)
)

var (
	sizeOfMessagePing = binary.Size(MessagePing{})
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
	err := pingData.Write(result)
	if err != nil {
		panic(err)
	}
	return result
}

func (pingData *MessagePingData) Write(b []byte) error {
	return pingData.WriteTo(bytes.NewBuffer(b))
}

func (pingData *MessagePingData) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, pingData)
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
	err := ping.Write(result)
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

func (ping *MessagePing) Write(b []byte) error {
	return ping.WriteTo(bytes.NewBuffer(b))
}

func (ping *MessagePing) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, ping)
}
