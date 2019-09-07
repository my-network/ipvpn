package network

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	discoveredPeerAddrDuration = discoveryInterval * 4
)

type discoveredPeerAddrs struct {
	locker sync.Mutex

	mesh *Network

	storage map[peer.ID]*discoveredPeerAddrsItem
}

type discoveredPeerAddrsItem struct {
	locker sync.Mutex

	parent *discoveredPeerAddrs

	peerID           peer.ID
	addrs            []*discoveredPeerAddrItem
	lastAccumulateTS time.Time
	lastConsiderTS   time.Time
	waiterContext    context.Context
}

type discoveredPeerAddrItem struct {
	addr             multiaddr.Multiaddr
	lastAccumulateTS time.Time
}

func newDiscoveredPeerAddrs(mesh *Network) *discoveredPeerAddrs {
	return &discoveredPeerAddrs{
		mesh:    mesh,
		storage: map[peer.ID]*discoveredPeerAddrsItem{},
	}
}

func (m *discoveredPeerAddrs) LockDo(fn func()) {
	m.locker.Lock()
	defer m.locker.Unlock()
	fn()
}

func (m *discoveredPeerAddrs) GC() {
	now := time.Now()
	m.LockDo(func() {
		for peerID, item := range m.storage {
			if now.Sub(item.lastAccumulateTS) > discoveredPeerAddrDuration {
				delete(m.storage, peerID)
			}
		}
	})
}

func (m *discoveredPeerAddrs) OfPeer(peerID peer.ID) (item *discoveredPeerAddrsItem) {
	m.GC()

	m.LockDo(func() {
		item = m.storage[peerID]
		if item == nil {
			item = &discoveredPeerAddrsItem{
				parent: m,
				peerID: peerID,
			}
			m.storage[peerID] = item
		}
	})
	return
}

func (i *discoveredPeerAddrsItem) LockDo(fn func()) {
	i.locker.Lock()
	defer i.locker.Unlock()
	fn()
}

func (i *discoveredPeerAddrsItem) GC() {
	now := time.Now()

	i.LockDo(func() {
		var cleanAddrs []*discoveredPeerAddrItem
		for _, oldAddr := range i.addrs {
			if now.Sub(oldAddr.lastAccumulateTS) > discoveredPeerAddrDuration {
				continue
			}

			cleanAddrs = append(cleanAddrs, oldAddr)
		}

		i.addrs = cleanAddrs
	})
}

func (i *discoveredPeerAddrsItem) AccumulateAddrs(addrs []multiaddr.Multiaddr) {
	i.GC()

	now := time.Now()
	i.LockDo(func() {
		i.lastAccumulateTS = now

		for _, addr := range addrs {
			if len(i.addrs) >= 255 {
				i.parent.mesh.logger.Error(`peer `, i.peerID, ` has too many discovered addresses. Skip `, addr)
				continue
			}

			found := false
			for _, oldAddr := range i.addrs {
				if oldAddr.addr.String() == addr.String() {
					oldAddr.lastAccumulateTS = now
					found = true
					break
				}
			}

			if found {
				continue
			}

			i.addrs = append(i.addrs, &discoveredPeerAddrItem{
				addr:             addr,
				lastAccumulateTS: now,
			})
		}

	})

	i.startWaiterIfNotStarted(discoveryInterval*2 + time.Second)
}

func (i *discoveredPeerAddrsItem) startWaiterIfNotStarted(waitDuration time.Duration) {
	i.LockDo(func() {
		if i.waiterContext != nil {
			return
		}

		i.waiterContext = context.Background()

		go func() {
			defer i.LockDo(func() {
				i.waiterContext = nil
			})

			timer := time.NewTimer(waitDuration)
			defer timer.Stop()

			select {
			case <-i.waiterContext.Done():
			case <-timer.C:
				i.considerAddrs()
			}
		}()
	})
}

func (i *discoveredPeerAddrsItem) considerAddrs() {
	var addrInfo AddrInfo
	i.GC()
	i.LockDo(func() {
		addrInfo.ID = i.peerID
		for _, addr := range i.addrs {
			addrInfo.Addrs = append(addrInfo.Addrs, addr.addr)
		}
	})

	i.parent.mesh.considerPeerAddr(addrInfo)
}
