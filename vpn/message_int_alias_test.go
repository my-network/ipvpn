package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizeOfMessageIntAlias(t *testing.T) {
	assert.True(t, sizeOfMessageIntAlias > 0, sizeOfMessageIntAlias)
}
