package vpn

import (
	"math"
)

var randIntnPosition uint32

// randIntn is a fast analog of rand.Intn. It's not thread-safe in formal terms, but it's not important :)
func randIntn(n uint32) uint32 {
	// Just two arbitrary prime numbers:
	randIntnPosition = 3948558707 * (randIntnPosition + 1948560947)
	if n == math.MaxUint32 {
		return randIntnPosition
	}
	return randIntnPosition % n
}

func randFloat64() float64 {
	return float64(randIntn(math.MaxUint32)) / float64(math.MaxUint32)
}
