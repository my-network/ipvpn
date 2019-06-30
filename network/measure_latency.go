package network

import (
	"context"
	"github.com/sparrc/go-ping"
	"github.com/xaionaro-go/errors"
	"math"
	"net"
	"time"

	p2pcore "github.com/libp2p/go-libp2p-core"
	"github.com/multiformats/go-multiaddr"
)

func (mesh *Network) measureLatencyToMultiaddr(ctx context.Context, addr p2pcore.Multiaddr) time.Duration {
	portStr, err := addr.ValueForProtocol(multiaddr.P_TCP)
	if err != nil {
		portStr, err = addr.ValueForProtocol(multiaddr.P_UDP)
	}
	if err != nil {
		mesh.logger.Debugf("unable to get TCP/UDP port from multiaddress \"%v\": %v", addr.String(), err)
		return math.MaxInt64
	}
	if portStr != ipfsPortString {
		mesh.logger.Debugf("NAT-ed port, seems to be unreachable", addr.String(), err)
		return math.MaxInt64 / 4
	}

	addr4, err := addr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		mesh.logger.Debugf("unable to get IPv4 address from multiaddress \"%v\": %v", addr.String(), err)
		return math.MaxInt64
	}

	return mesh.measureLatency(ctx, net.ParseIP(addr4))
}

func (mesh *Network) measureLatency(ctx context.Context, ip net.IP) (result time.Duration) {
	defer func() {
		mesh.logger.Debugf("measureLatency(ctx, \"%v\") -> %v", ip.String(), result)
	}()

	if ip.IsLoopback() {
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
			mesh.logger.Error(errors.Wrap(err))
			return
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			mesh.logger.Error(errors.Wrap(nil, `no timeout defined`))
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

	select {
	case <-ctx.Done():
		return math.MaxInt64 / 2
	case <-chTCP1:
		return time.Since(start)
	case <-chTCP80:
		return time.Since(start)
	case <-chICMP:
		return time.Since(start)
	}
}
