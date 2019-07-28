package vpn

import (
	"bytes"
	"encoding/binary"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
	"io"
)

var (
	sizeOfMessagePong = binary.Size(MessagePong{})
)

type MessagePongData struct {
	MessagePing
	ReceiveTS int64
	SendTS    int64
}

type MessagePong struct {
	MessagePongData
	RecipientSignature [ed25519.SignatureSize]byte
}

func (pongData *MessagePongData) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, binary.Size(pongData)))
	err := binary.Write(buf, binary.LittleEndian, pongData)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (pong *MessagePong) SignRecipient(privKey ed25519.PrivateKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	/*signature, err := privKey.Sign(rand.Reader, pong.MessagePongData.Bytes(), crypto.Hash(0))
	if err != nil {
		return
	}*/
	signature := ed25519.Sign(privKey, pong.MessagePongData.Bytes())
	copy(pong.RecipientSignature[:], signature)
	return
}

func (pong *MessagePong) VerifyRecipient(pubKey ed25519.PublicKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	isValidSignature := ed25519.Verify(pubKey, pong.MessagePongData.Bytes(), pong.RecipientSignature[:])
	if !isValidSignature {
		return ErrInvalidSignature
	}
	return
}

func (pong *MessagePong) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, binary.Size(pong)))
	err := pong.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (pong *MessagePong) Read(b []byte) error {
	if len(b) != binary.Size(pong) {
		return errors.Wrap(ErrInvalidSize, len(b), binary.Size(pong))
	}

	return errors.Wrap(binary.Read(bytes.NewReader(b), binary.LittleEndian, pong))
}

func (pong *MessagePong) Write(b []byte) error {
	return pong.WriteTo(bytes.NewBuffer(b))
}

func (pong *MessagePong) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, pong)
}
