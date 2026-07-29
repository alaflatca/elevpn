package server

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type peer struct {
	id       uint64
	addr     *net.UDPAddr
	tunnelIP netip.Addr
	lastSeen time.Time
}

type peerStore struct {
	mutex      sync.RWMutex
	byID       map[uint64]*peer
	byTunnelIP map[netip.Addr]*peer
	nextID     uint64
}

func newPeerStore() *peerStore {
	return &peerStore{
		byID:       make(map[uint64]*peer),
		byTunnelIP: make(map[netip.Addr]*peer),
		nextID:     1,
	}
}

func (ps *peerStore) register(addr *net.UDPAddr) (peer, error) {
	if addr == nil {
		return peer{}, fmt.Errorf("register addr is nil")
	}

	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	id := ps.nextID
	p := &peer{
		id:       id,
		addr:     addr,
		lastSeen: time.Now(),
	}
	ps.byID[id] = p

	ps.nextID++
	return *p, nil
}

func (ps *peerStore) setTunnelIP(id uint64, tunnelIP netip.Addr) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	p, ok := ps.byID[id]
	if !ok {
		return fmt.Errorf("not found peer id=%d", id)
	}
	if p == nil {
		return fmt.Errorf("peer is nil: id=%d", id)
	}

	_, ok = ps.byTunnelIP[tunnelIP]
	if ok {
		return fmt.Errorf("already exists tunnel ip=%v", tunnelIP.String())
	}

	p.tunnelIP = tunnelIP
	ps.byTunnelIP[tunnelIP] = p

	return nil
}

func (ps *peerStore) getByID(id uint64) (peer, bool) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	p, ok := ps.byID[id]
	if !ok || p == nil {
		return peer{}, false
	}

	return *p, true
}

func (ps *peerStore) getByTunnelIP(ip netip.Addr) (peer, bool) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	p, ok := ps.byTunnelIP[ip]
	if !ok || p == nil {
		return peer{}, false
	}

	return *p, true
}

func (ps *peerStore) touch(id uint64) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	p, ok := ps.byID[id]
	if !ok || p == nil {
		return fmt.Errorf("not found peer id=%d", id)
	}

	p.lastSeen = time.Now()
	return nil
}
