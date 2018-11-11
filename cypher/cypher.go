package cypher

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"

	"golang.org/x/crypto/ed25519"
)

const (
	publicFileName  = "public.pem"
	privateFileName = "private.pem"
)

type keys struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

type cypher struct {
	keys keys
}

type CypherT = cypher

func init() {
	switch runtime.GOOS {
	case "linux":
		// by default Golang uses /dev/urandom which is insecure for crypto purposes
		devRandom, err := os.Open(`/dev/random`)
		if err != nil {
			rand.Reader = devRandom
		}
	}
}

func New(keysDir string) (*cypher, error) {
	c := &cypher{}
	return c, c.prepareKeys(keysDir)
}

func (c *cypher) savePublicKey(keysDir string) error {
	return saveKeyToPemFile(
		"ED25519 PUBLIC KEY",
		c.keys.Public,
		filepath.Join(keysDir, publicFileName),
	)
}

func (c *cypher) savePrivateKey(keysDir string) error {
	return saveKeyToPemFile(
		"ED25519 PRIVATE KEY",
		c.keys.Private,
		filepath.Join(keysDir, privateFileName),
	)
}

func saveKeyToPemFile(keyType string, key []byte, filePath string) error {
	keyFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	keyBlock := pem.Block{
		Type:    keyType,
		Headers: nil,
		Bytes:   key,
	}

	return pem.Encode(keyFile, &keyBlock)
}

func (c *cypher) generateAndSaveKeys(keysDir string) error {
	var err error
	c.keys.Public, c.keys.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Cannot generate keys")
	}
	err = c.savePrivateKey(keysDir)
	c.savePublicKey(keysDir)
	return errors.Wrap(err, "Cannot save keys")
}

func loadPrivateKeyFromFile(keyPtr *ed25519.PrivateKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("Read key is of wrong length: %d != %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	*keyPtr = block.Bytes
	return nil
}

func (c *cypher) loadKeys(keysDir string) error {
	err := loadPrivateKeyFromFile(&c.keys.Private, filepath.Join(keysDir, privateFileName))
	if err != nil {
		return errors.Wrap(err, "Cannot load the private key")
	}
	c.keys.Public = c.keys.Private.Public().(ed25519.PublicKey)
	return nil
}

func (c *cypher) prepareKeys(keysDir string) error {
	err := os.MkdirAll(keysDir, os.FileMode(0700))
	if err != nil {
		return errors.Wrap(err, "Cannot create the directory: "+keysDir)
	}
	if _, err := os.Stat(filepath.Join(keysDir, privateFileName)); os.IsNotExist(err) {
		return c.generateAndSaveKeys(keysDir)
	}
	err = c.loadKeys(keysDir)
	if _, err := os.Stat(filepath.Join(keysDir, publicFileName)); os.IsNotExist(err) {
		c.savePublicKey(keysDir)
	}
	return errors.Wrap(err, "Cannot load keys")
}

func (c *cypher) GetKeys() keys {
	return c.keys
}
