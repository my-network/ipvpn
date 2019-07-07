package vpn

import (
	"sync"
	"time"
)

type channelStatistics struct {
	locker sync.RWMutex

	SamplesCount uint64
	RTT          time.Duration
}
