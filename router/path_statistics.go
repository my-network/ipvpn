package router

import (
	"sync"
	"time"
)

const (
	inertiaFactor = 5
)

type PathStatistics struct {
	locker sync.RWMutex

	count    uint64
	timedOut float64
	latency  time.Duration
}

func (stats *PathStatistics) LockDo(fn func()) {
	stats.locker.Lock()
	defer stats.locker.Unlock()
	fn()
}

func (stats *PathStatistics) RLockDo(fn func()) {
	stats.locker.RLock()
	defer stats.locker.RUnlock()
	fn()
}

func (stats *PathStatistics) Consider(latency time.Duration, isLoss bool) {
	stats.LockDo(func() {
		inertiaFactorCur := uint64(inertiaFactor)
		if stats.count < inertiaFactor {
			inertiaFactorCur = stats.count
		}
		stats.count++

		timedOut := float64(0)
		if isLoss {
			timedOut = 1
		}
		stats.timedOut = (stats.timedOut*float64(inertiaFactorCur) + timedOut) / (float64(inertiaFactorCur) + 1)

		if !isLoss {
			stats.latency = time.Duration((uint64(stats.latency)*inertiaFactorCur + uint64(latency)) / (inertiaFactorCur + 1))
		}
	})
}

func (stats *PathStatistics) Latency() (result time.Duration) {
	stats.RLockDo(func() {
		result = stats.latency
	})
	return
}

func (stats *PathStatistics) TimedOut() (result float64) {
	stats.RLockDo(func() {
		result = stats.timedOut
	})
	return
}
