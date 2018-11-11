package helpers

import (
	"crypto/sha512"
)

var (
	salt = []byte("homenetp")
)

func Hash(in []byte) []byte {
	sum := sha512.Sum512(append(salt, in...))
	return append(salt, sum[:]...)
}
