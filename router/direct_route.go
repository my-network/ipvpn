package router

import (
	"context"
	"math"
	"net"
	"sync"
	"time"

	"github.com/my-network/ipvpn/helpers"
)

type DirectRoute struct {
	locker sync.RWMutex

	channelType          ChannelType
	peer                 *Peer
	destination          net.IP
	lastLatencyMeasureTS time.Time
	statistics           PathStatistics
}

func newDirectRoute(peer *Peer, chType ChannelType, destination net.IP) *DirectRoute {
	return &DirectRoute{
		peer:        peer,
		channelType: chType,
		destination: destination,
	}
}

func (route *DirectRoute) lockDo(fn func()) {
	route.locker.Lock()
	defer route.locker.Unlock()
	fn()
}

func (route *DirectRoute) rLockDo(fn func()) {
	route.locker.RLock()
	defer route.locker.RUnlock()
	fn()
}

func (route *DirectRoute) MeasureLatency(ctx context.Context) {
	if route == nil {
		return
	}

	defer route.lockDo(func() {
		route.lastLatencyMeasureTS = time.Now()
	})

	for i := 0; i < 2*inertiaFactor; i++ {
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		latency := helpers.MeasureLatency(ctx, route.destination, route.peer.router.logger)
		route.statistics.Consider(latency, latency >= math.MaxInt64/4)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (route *DirectRoute) Latency() time.Duration {
	if route == nil {
		return 365 * 24 * time.Hour
	}

	return route.statistics.Latency()
}

func (route *DirectRoute) TimedOutFraction() float64 {
	if route == nil {
		return 1
	}

	return route.statistics.TimedOut()
}

func (route *DirectRoute) Destination() (result net.IP) {
	if route == nil {
		return nil
	}

	route.rLockDo(func() {
		result = route.destination
	})
	return
}

func (route *DirectRoute) SetDestination(ip net.IP) {
	route.lockDo(func() {
		route.destination = ip
	})
}

func (route *DirectRoute) ChannelType() ChannelType {
	if route == nil {
		return ChannelType_undefined
	}

	return route.channelType
}
