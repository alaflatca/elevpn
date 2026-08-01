package server

import (
	"context"
	"elevpn/internal/protocol"
	"elevpn/internal/tun"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
)

var ErrDropPacket = errors.New("drop packet")

func (s *Server) handleAloha(conn *net.UDPConn, peerAddr *net.UDPAddr) error {
	if conn == nil {
		return errors.New("conn is nil")
	}
	if peerAddr == nil {
		return errors.New("peerAddr is nil")
	}

	peer, err := s.peers.register(peerAddr)
	if err != nil {
		return err
	}
	log.Printf("[handshake] received ALOHA from %s", peerAddr.String())

	tunnelIP, err := s.allocateTunnelIP(peer.id)
	if err != nil {
		return err
	}
	if err := s.peers.setTunnelIP(peer.id, tunnelIP); err != nil {
		return err
	}
	log.Printf("[handshake] registered peer id=%d tunnel_ip=%s mtu=%d", peer.id, tunnelIP.String(), protocol.DefaultTunnelMTU)

	var payload [6]byte
	ip4 := tunnelIP.As4()
	copy(payload[0:4], ip4[:])
	binary.BigEndian.PutUint16(payload[4:6], protocol.DefaultTunnelMTU)

	msg := &protocol.Message{
		Type:    protocol.MessageTypeWelcome,
		PeerID:  peer.id,
		Payload: payload[:], // 나중에 payload가 많아지면 offset 별로 정리해서 데이터 추가
		// 0:4, tunnel IP
		// 4:5, mtu
	}

	welcomePacket, err := protocol.Encode(msg)
	if err != nil {
		return err
	}

	written, err := conn.WriteToUDP(welcomePacket, peerAddr)
	if err != nil {
		return err
	}

	if written != len(welcomePacket) {
		return io.ErrShortWrite
	}
	log.Printf("[handshake] sent WELCOME peer_id=%d tunnel_ip=%s mtu=%d", peer.id, tunnelIP.String(), protocol.DefaultTunnelMTU)

	return nil
}

func (s *Server) allocateTunnelIP(peerID uint64) (netip.Addr, error) {
	_, ipnet, err := net.ParseCIDR(s.cfg.VPNNetworkCIDR)
	if err != nil {
		return netip.Addr{}, err
	}
	if ipnet.IP.To4() == nil {
		return netip.Addr{}, fmt.Errorf("invalid ipv4")
	}

	ones, _ := ipnet.Mask.Size()
	if !validIPRange(peerID, ones) {
		return netip.Addr{}, fmt.Errorf("invalid ip range: peerID=%d prefix=%d", peerID, ones)
	}

	vpnNetworkBase := binary.BigEndian.Uint32(ipnet.IP.To4())
	tunnelIPUint := vpnNetworkBase + 1 + uint32(peerID)

	var tunnelAddr [4]byte
	binary.BigEndian.PutUint32(tunnelAddr[:], tunnelIPUint)
	tunnelIP := netip.AddrFrom4(tunnelAddr)

	if !tunnelIP.Is4() {
		return netip.Addr{}, fmt.Errorf("tunnel ip is not ipv4")
	}

	return tunnelIP, nil
}

func validIPRange(peerID uint64, prefix int) bool {
	if peerID == 0 {
		return false
	}
	if prefix < 0 || prefix > 30 {
		return false
	}

	hostBits := 32 - prefix //prefix 24 --> 32-24 = 8
	total := 1 << hostBits  // 1 << 8 ---> 256
	maxPeerID := total - 3  // 253 ---> base(0) + 1 + 253 --> 최대 254

	if peerID > uint64(maxPeerID) {
		return false
	}

	return true
}

func (s *Server) handleKeepalive(peerID uint64) error {
	if err := s.peers.touch(peerID); err != nil {
		return err
	}
	log.Printf("[keepalive] peer_id=%d last_seen updated", peerID)

	return nil
}

func (s *Server) handleData(ctx context.Context, tun *tun.Tun, peerAddr *net.UDPAddr, message protocol.Message) error {
	if peerAddr == nil {
		return fmt.Errorf("peer addr is nil: %w", ErrDropPacket)
	}
	if len(message.Payload) == 0 {
		return fmt.Errorf("peer(%s:%d) payload is empty: %w", peerAddr.IP.String(), peerAddr.Port, ErrDropPacket)
	}

	peer, ok := s.peers.getByID(message.PeerID)
	if !ok {
		return fmt.Errorf("peer not found: id=%d: %w", message.PeerID, ErrDropPacket)
	}
	if peer.addr == nil {
		return fmt.Errorf("peer addr is nil (id=%d): %w", message.PeerID, ErrDropPacket)
	}
	if !peer.addr.IP.Equal(peerAddr.IP) {
		return fmt.Errorf("mismatch ip: expected=%s actual=%s: %w", peer.addr.IP.String(), peerAddr.IP.String(), ErrDropPacket)
	}
	if peer.addr.Port != peerAddr.Port {
		return fmt.Errorf("mismatch port: expected=%d actual=%d: %w", peer.addr.Port, peerAddr.Port, ErrDropPacket)
	}

	written, err := tun.WriteContext(ctx, message.Payload)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if written != len(message.Payload) {
		return io.ErrShortWrite
	}

	if err := s.peers.touch(peer.id); err != nil {
		return fmt.Errorf("failed to touch peer id=%d: %v", peer.id, err)
	}

	return nil
}
