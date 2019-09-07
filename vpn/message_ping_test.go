package vpn

import (
	"bytes"
	"crypto/ed25519"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessagePingWriteToReadFrom(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(0)))
	_ = pubKey

	assert.NoError(t, err)

	msg := &MessagePing{}
	msg.SendTS = 1
	msg.SequenceID = 2
	msg.SignSender(privKey)

	buf := bytes.NewBuffer(nil)
	err = msg.WriteTo(buf)
	assert.NoError(t, err)

	decodedMsg := &MessagePing{}
	err = decodedMsg.ReadFrom(buf)
	assert.NoError(t, err)

	assert.Equal(t, msg, decodedMsg)
}

func TestMessagePingWriteRead(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(0)))
	_ = pubKey

	assert.NoError(t, err)

	msg := &MessagePing{}
	msg.SendTS = 1
	msg.SequenceID = 2
	msg.SignSender(privKey)

	buf := make([]byte, sizeOfMessagePing)
	err = msg.Write(buf)
	assert.NoError(t, err)
	assert.NotEqual(t, buf, make([]byte, sizeOfMessagePing))

	decodedMsg := &MessagePing{}
	err = decodedMsg.Read(buf)
	assert.NoError(t, err)

	assert.Equal(t, msg, decodedMsg)
}
