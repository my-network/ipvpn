package helpers

import (
	"context"
	"math"
	"net"
	"time"

	"github.com/go-ping/ping"
	"github.com/xaionaro-go/errors"
)

func MeasureLatency(ctx context.Context, ip net.IP, logger Logger) (result time.Duration) {
	defer func() {
		logger.Debugf("measureLatency(ctx, \"%v\") -> %v", ip.String(), result)
	}()

	if ip.IsLoopback() {
		// There's no sense to measure latency to the localhost
		return math.MaxInt64
	}

	start := time.Now()
	chTCP1 := make(chan struct{})
	chTCP80 := make(chan struct{})
	chICMP := make(chan struct{})

	go func() {
		conn, _ := net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   ip,
			Port: 1,
		})
		close(chTCP1)
		if conn != nil {
			_ = conn.Close()
		}
	}()

	go func() {
		conn, _ := net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   ip,
			Port: 80,
		})
		close(chTCP80)
		if conn != nil {
			_ = conn.Close()
		}
	}()

	go func() {
		pinger, err := ping.NewPinger(ip.String())
		if err != nil {
			logger.Error(errors.Wrap(err))
			return
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			logger.Error(errors.Wrap(nil, `no timeout defined`))
		} else {
			pinger.Timeout = deadline.Sub(start)
		}

		pinger.SetPrivileged(true)
		pinger.Count = 1
		pinger.Run()
		stats := pinger.Statistics()
		if stats.PacketLoss != 0 {
			select {
			case <-ctx.Done():
			}
		}
		close(chICMP)
	}()

	var t time.Duration
	select {
	case <-ctx.Done():
		t = math.MaxInt64 / 2
		logger.Debugf("got timeout: %v", ip.String())
	case <-chTCP1:
		t = time.Since(start)
		logger.Debugf("got signal chTCP1: %v", ip.String())
	case <-chTCP80:
		t = time.Since(start)
		logger.Debugf("got signal chTCP80: %v", ip.String())
	case <-chICMP:
		t = time.Since(start)
		logger.Debugf("got signal chICMP: %v", ip.String())
	}
	return t
}
