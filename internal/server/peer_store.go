package server

import (
	"elevpn/internal/protocol"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type peerStore struct {
	mu sync.RWMutex

	byID           map[uint64]*peer
	byTunnelIP     map[netip.Addr]*peer
	byClientRandom map[protocol.HandshakeRandom]*peer

	nextID uint64
}

func newPeerStore() *peerStore {
	return &peerStore{
		byID:           make(map[uint64]*peer),
		byTunnelIP:     make(map[netip.Addr]*peer),
		byClientRandom: make(map[protocol.HandshakeRandom]*peer),
		nextID:         1,
	}
}

func (ps *peerStore) register(addr *net.UDPAddr, clientRandom protocol.HandshakeRandom) (*peer, bool, error) {
	if addr == nil {
		return nil, false, fmt.Errorf("register addr is nil")
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	if p, found := ps.byClientRandom[clientRandom]; found {
		return p, false, nil
	}

	id := ps.nextID
	p := &peer{
		id:           id,
		addr:         addr,
		clientRandom: clientRandom,
		lastSeen:     time.Now(),
	}
	ps.nextID++
	ps.byID[id] = p
	ps.byClientRandom[clientRandom] = p

	return p, true, nil
}

func (ps *peerStore) getByID(id uint64) (*peer, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	p, ok := ps.byID[id]
	if !ok || p == nil {
		return nil, ErrDropPacket
	}

	return p, nil
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
			delete(ps.byClientRandom, peer.clientRandom)
			deleteCount++
		}
	}

	return deleteCount
}
