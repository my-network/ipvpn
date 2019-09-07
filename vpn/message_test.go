package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizeOfMessageType(t *testing.T) {
	assert.Equal(t, 2, sizeOfMessageType)
}
