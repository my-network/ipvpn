package vpn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

type MessagePongData struct {
	MessagePing
	ReceiveTS time.Time
	SendTS    time.Time
}

type MessagePong struct {
	MessagePongData
	RecipientSignature [ed25519.SignatureSize]byte
}

func (pongData *MessagePongData) Bytes() []byte {
	result := make([]byte, binary.Size(pongData))
	err := binary.Write(bytes.NewBuffer(result), binary.LittleEndian, pongData)
	if err != nil {
		panic(err)
	}
	return result
}

func (pong *MessagePong) SignRecipient(privKey ed25519.PrivateKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	signature, err := privKey.Sign(rand.Reader, pong.MessagePongData.Bytes(), nil)
	if err != nil {
		return
	}
	copy(pong.RecipientSignature[:], signature)
	return
}

func (pong *MessagePong) VerifyRecipient(pubKey ed25519.PublicKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	isValidSignature := ed25519.Verify(pubKey, pong.RecipientSignature[:], pong.MessagePongData.Bytes())
	if !isValidSignature {
		return ErrInvalidSignature
	}
	return
}

func (pong *MessagePong) Bytes() []byte {
	result := make([]byte, binary.Size(pong))
	err := binary.Write(bytes.NewBuffer(result), binary.LittleEndian, pong)
	if err != nil {
		panic(err)
	}
	return result
}

func (pong *MessagePong) Read(b []byte) error {
	if len(b) != binary.Size(pong) {
		return errors.Wrap(ErrInvalidSize, len(b), binary.Size(pong))
	}

	return errors.Wrap(binary.Read(bytes.NewReader(b), binary.LittleEndian, pong))
}
