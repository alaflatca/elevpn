package server

import (
	"context"
	"elevpn/internal/protocol"
	"elevpn/internal/tun"
	"errors"
	"fmt"
	"io"
	"net"
)

var ErrDropPacket = errors.New("drop packet")

func (s *Server) handleAloha(conn *net.UDPConn, peerAddr *net.UDPAddr) error {
	peer, err := s.peers.register(peerAddr)
	if err != nil {
		return err
	}

	msg := &protocol.Message{
		Type:   protocol.MessageTypeWelcome,
		PeerID: peer.id,
		// Payload: , // 나중에 tunnel IP 포함
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

	return nil
}

func (s *Server) handleKeepalive() error {
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
