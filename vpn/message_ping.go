package vpn

import (
	"bytes"
	"encoding/binary"
	e "errors"
	"io"

	"github.com/xaionaro-go/bytesextra"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

var (
	ErrInvalidSignature = e.New(`invalid signature`)
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
	buf := bytes.NewBuffer(make([]byte, binary.Size(pingData)))
	err := pingData.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (pingData *MessagePingData) Write(b []byte) error {
	return pingData.WriteTo(bytesextra.NewReadWriteSeeker(b))
}

func (pingData *MessagePingData) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, pingData)
}

func (ping *MessagePing) SignSender(privKey ed25519.PrivateKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	/*signature, err := privKey.Sign(rand.Reader, ping.MessagePingData.Bytes(), crypto.Hash(0))
	if err != nil {
		return
	}*/
	signature := ed25519.Sign(privKey, ping.MessagePingData.Bytes())
	copy(ping.SenderSignature[:], signature)
	return
}

func (ping *MessagePing) VerifySender(pubKey ed25519.PublicKey) (err error) {
	defer func() { err = errors.Wrap(err) }()

	isValidSignature := ed25519.Verify(pubKey, ping.MessagePingData.Bytes(), ping.SenderSignature[:])
	if !isValidSignature {
		return ErrInvalidSignature
	}
	return
}

func (ping *MessagePing) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, binary.Size(ping)))
	err := ping.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (ping *MessagePing) Read(b []byte) error {
	if len(b) != binary.Size(ping) {
		return errors.Wrap(ErrInvalidSize, len(b), binary.Size(ping))
	}

	return ping.ReadFrom(bytes.NewReader(b))
}

func (ping *MessagePing) ReadFrom(reader io.Reader) error {
	return errors.Wrap(binary.Read(reader, binary.LittleEndian, ping))
}

func (ping *MessagePing) Write(b []byte) error {
	return ping.WriteTo(bytesextra.NewReadWriteSeeker(b))
}

func (ping *MessagePing) WriteTo(writer io.Writer) error {
	return binary.Write(writer, binary.LittleEndian, ping)
}
