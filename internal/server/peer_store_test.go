package server

import (
	"elevpn/internal/protocol"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestPeerStoreRegisterNewAndDuplicatePeer(t *testing.T) {
	ps := newPeerStore()
	random := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp addr: %v", err)
	}

	firstPeer, created, err := ps.register(addr, random)
	if err != nil {
		t.Fatalf("failed to register peer: addr=%v random=%v: %v", addr, random, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if firstPeer == nil {
		t.Fatal("expected registered peer, got nil")
	}

	secondPeer, created, err := ps.register(addr, random)
	if err != nil {
		t.Fatalf("failed to register duplicate peer: %v", err)
	}
	if created {
		t.Fatal("expected duplicate registration to reuse existing peer")
	}
	if firstPeer != secondPeer {
		t.Fatal("expected the same peer to be returned")
	}

	if len(ps.byID) != 1 {
		t.Fatalf("expected one peer in byID, got: %d", len(ps.byID))
	}
	if len(ps.byClientRandom) != 1 {
		t.Fatalf("expected one peer in byClientRandom, got: %d", len(ps.byClientRandom))
	}

	if ps.byID[firstPeer.id] != firstPeer {
		t.Fatal("expected first peer to be stored in byID")
	}
	if ps.byClientRandom[random] != firstPeer {
		t.Fatal("expected first peer to be stored in byClientRandom")
	}

	if ps.nextID != 2 {
		t.Fatalf("expected nextID to remain 2 after duplicate registration, got: %d", ps.nextID)
	}
}

func TestPeerStoreRegisterDifferentClientRandom(t *testing.T) {
	ps := newPeerStore()
	firstRandom := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	secondRandom := protocol.HandshakeRandom{
		0, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	firstAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp first addr: %v", err)
	}
	secondAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp second addr: %v", err)
	}

	firstPeer, created, err := ps.register(firstAddr, firstRandom)
	if err != nil {
		t.Fatalf("failed to register peer: addr=%v random=%v: %v", firstAddr, firstRandom, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if firstPeer == nil {
		t.Fatal("expected registered peer, got nil")
	}
	if firstPeer.id != 1 {
		t.Fatalf("expected first peer ID to be 1, got: %d", firstPeer.id)
	}

	secondPeer, created, err := ps.register(secondAddr, secondRandom)
	if err != nil {
		t.Fatalf("failed to register peer: addr=%v random=%v: %v", secondAddr, secondRandom, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if secondPeer == nil {
		t.Fatal("expected registered peer, got nil")
	}
	if secondPeer.id != 2 {
		t.Fatalf("expected second peer ID to be 2, got: %d", secondPeer.id)
	}

	if firstPeer == secondPeer {
		t.Fatal("expected different peers, got the same peer")
	}

	if len(ps.byID) != 2 {
		t.Fatalf("expected two peers in byID, got: %d", len(ps.byID))
	}
	if len(ps.byClientRandom) != 2 {
		t.Fatalf("expected two peers in byClientRandom, got: %d", len(ps.byClientRandom))
	}

	if ps.byID[firstPeer.id] != firstPeer {
		t.Fatal("expected first peer to be stored in byID")
	}
	if ps.byClientRandom[firstPeer.clientRandom] != firstPeer {
		t.Fatal("expected first peer to be stored in byClientRandom")
	}

	if ps.byID[secondPeer.id] != secondPeer {
		t.Fatal("expected second peer to be stored in byID")
	}
	if ps.byClientRandom[secondPeer.clientRandom] != secondPeer {
		t.Fatal("expected second peer to be stored in byClientRandom")
	}

	if ps.nextID != 3 {
		t.Fatalf("expected nextID to be 3 after registering two peers, got: %d", ps.nextID)
	}
}

func TestPeerStoreRegisterRejectsNilAddr(t *testing.T) {
	ps := newPeerStore()
	random := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	peer, created, err := ps.register(nil, random)
	if err == nil {
		t.Fatal("expected registration with a nil address to fail")
	}
	if peer != nil {
		t.Fatal("expected peer to be nil")
	}
	if created {
		t.Fatal("expected peer not to be created")
	}
	if len(ps.byID) != 0 || len(ps.byClientRandom) != 0 || len(ps.byTunnelIP) != 0 {
		t.Fatal("expected peer store to remain empty")
	}

	if ps.nextID != 1 {
		t.Fatalf("expected nextID to remain 1, got: %d", ps.nextID)
	}
}

func TestPeerStoreGetByIDReturnsRegisteredPeer(t *testing.T) {
	ps := newPeerStore()
	random := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp addr: %v", err)
	}

	peer, created, err := ps.register(addr, random)
	if err != nil {
		t.Fatalf("failed to register peer: addr=%v random=%v: %v", addr, random, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if peer == nil {
		t.Fatal("expected registered peer, got nil")
	}
	if peer.id != 1 {
		t.Fatalf("expected peerID to be 1, got: %d", peer.id)
	}

	got, err := ps.getByID(peer.id)
	if err != nil {
		t.Fatalf("failed to get peer by ID: id=%d: %v", peer.id, err)
	}
	if peer != got {
		t.Fatal("expected the same peer, got a different peer")
	}
}

func TestPeerStoreGetByIDReturnsErrorForUnknownID(t *testing.T) {
	ps := newPeerStore()
	peer, err := ps.getByID(1)
	if !errors.Is(err, ErrDropPacket) {
		t.Fatalf("expected ErrDropPacket for unknown peer ID, got: %v", err)
	}
	if peer != nil {
		t.Fatalf("expected peer to be nil, got: %+v", peer)
	}
}

func TestPeerStoreSetAndGetByTunnelIP(t *testing.T) {
	ps := newPeerStore()
	random := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp first addr: %v", err)
	}

	peer, created, err := ps.register(addr, random)
	if err != nil {
		t.Fatalf("failed to register peer: addr=%v random=%v: %v", addr, random, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if peer == nil {
		t.Fatal("expected registered peer, got nil")
	}
	if peer.id != 1 {
		t.Fatalf("expected peerID to be 1, got: %d", peer.id)
	}

	tunnelIP := netip.MustParseAddr("10.77.0.2")
	if err := ps.setTunnelIP(peer.id, tunnelIP); err != nil {
		t.Fatalf("failed to set tunnel IP: peer_id=%d ip=%s: %v", peer.id, tunnelIP, err)
	}
	gotTunnelIP := peer.tunnelIPSnapshot()
	if gotTunnelIP != tunnelIP {
		t.Fatalf("expected peer tunnel IP to be %s, got: %s", tunnelIP, gotTunnelIP)
	}

	got, found := ps.getByTunnelIP(tunnelIP)
	if !found {
		t.Fatalf("expected peer to be found by tunnel IP: ip=%s", tunnelIP)
	}
	if got != peer {
		t.Fatal("expected the same peer, got a different peer")
	}
}

func TestPeerStoreSetTunnelIPRejectsDuplicateIP(t *testing.T) {
	ps := newPeerStore()
	firstRandom := protocol.HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	secondRandom := protocol.HandshakeRandom{
		0, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9010")
	if err != nil {
		t.Fatalf("invalid resolve udp first addr: %v", err)
	}

	firstPeer, created, err := ps.register(addr, firstRandom)
	if err != nil {
		t.Fatalf("failed to register first peer: addr=%v random=%v: %v", addr, firstRandom, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if firstPeer == nil {
		t.Fatal("expected registered first peer, got nil")
	}
	if firstPeer.id != 1 {
		t.Fatalf("expected peerID to be 1, got: %d", firstPeer.id)
	}

	secondPeer, created, err := ps.register(addr, secondRandom)
	if err != nil {
		t.Fatalf("failed to register second peer: addr=%v random=%v: %v", addr, secondRandom, err)
	}
	if !created {
		t.Fatal("expected a new peer to be created")
	}
	if secondPeer == nil {
		t.Fatal("expected registered second peer, got nil")
	}
	if secondPeer.id != 2 {
		t.Fatalf("expected peerID to be 2, got: %d", secondPeer.id)
	}

	tunnelIP := netip.MustParseAddr("10.77.0.2")
	if err := ps.setTunnelIP(firstPeer.id, tunnelIP); err != nil {
		t.Fatalf("failed to set first tunnel IP: peer_id=%d ip=%s: %v", firstPeer.id, tunnelIP, err)
	}
	if err := ps.setTunnelIP(secondPeer.id, tunnelIP); err == nil {
		t.Fatal("expected duplicate tunnel IP assignment to fail")
	}

	got, found := ps.getByTunnelIP(tunnelIP)
	if !found {
		t.Fatal("expected tunnel IP mapping to remain")
	}
	if got != firstPeer {
		t.Fatal("expected tunnel IP to remain assigned to the first peer")
	}
	if len(ps.byTunnelIP) != 1 {
		t.Fatalf("expected one tunnel IP mapping, got: %d", len(ps.byTunnelIP))
	}

}
