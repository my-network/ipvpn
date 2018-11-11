package helpers

import (
	"encoding/hex"
)

func ToHEX(b []byte) string {
	return hex.EncodeToString(b)
}
