package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type peer struct {
	mu       sync.RWMutex
	id       uint64
	addr     *net.UDPAddr
	tunnelIP netip.Addr
	lastSeen time.Time

	serverSendSequence uint64
	lastClientSequence uint64
}

type peerStore struct {
	mu         sync.RWMutex
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

func (p *peer) nextSendSequence() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.serverSendSequence++
	return p.serverSendSequence
}

func (p *peer) acceptClientSequence(seq uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if seq <= p.lastClientSequence {
		return ErrReplayPacket
	}
	p.lastClientSequence = seq
	return nil
}

func (p *peer) setTunnelIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.tunnelIP = ip
}

func (ps *peerStore) register(addr *net.UDPAddr) (*peer, error) {
	if addr == nil {
		return nil, fmt.Errorf("register addr is nil")
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	id := ps.nextID
	p := &peer{
		id:       id,
		addr:     addr,
		lastSeen: time.Now(),
	}
	ps.byID[id] = p

	ps.nextID++
	return p, nil
}

func (ps *peerStore) setTunnelIP(id uint64, tunnelIP netip.Addr) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

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

	p.setTunnelIP(tunnelIP)
	ps.byTunnelIP[tunnelIP] = p

	return nil
}

func (ps *peerStore) getByID(id uint64) (*peer, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	p, ok := ps.byID[id]
	if !ok || p == nil {
		return nil, false
	}

	return p, true
}

func (ps *peerStore) getByTunnelIP(ip netip.Addr) (*peer, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	p, ok := ps.byTunnelIP[ip]
	if !ok || p == nil {
		return nil, false
	}

	return p, true
}

func (p *peer) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastSeen = time.Now()
}

func (p *peer) expired(now time.Time, timeout time.Duration) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if now.Sub(p.lastSeen) > timeout {
		return true
	}
	return false
}

func (p *peer) tunnelIPSnapshot() netip.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tunnelIP := p.tunnelIP
	return tunnelIP
}

// deleteExpired에서 예상 가능한 실패가 거의 없기 때문에 error보다 count가 더 실용적
func (ps *peerStore) deleteExpired(now time.Time, timeout time.Duration) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	deleteCount := 0
	for id, peer := range ps.byID {
		if peer == nil {
			delete(ps.byID, id)
			deleteCount++

			log.Printf("[peer] nil peer entry removed peer_id=%d", id)
			continue
		}
		if peer.expired(now, timeout) {
			tunnelIP := peer.tunnelIPSnapshot()
			delete(ps.byID, id)
			delete(ps.byTunnelIP, tunnelIP)
			deleteCount++
		}
	}

	return deleteCount
}
