package server

import (
	"elevpn/internal/protocol"
	"fmt"
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

	cipher *protocol.Cipher

	serverSendSequence uint64
	clientReplayWindow protocol.ReplayWindow
}

func (p *peer) setCipher(cipher *protocol.Cipher) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cipher = cipher
}

func (p *peer) cipherSnapshot() *protocol.Cipher {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.cipher
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

	if err := p.clientReplayWindow.Accept(seq); err != nil {
		return fmt.Errorf("client sequence rejected: sequence=%d: %w", seq, err)
	}

	return nil
}

func (p *peer) setTunnelIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.tunnelIP = ip
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
