package client

import (
	"elevpn/internal/protocol"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

type handshakeResult struct {
	peerID   uint64
	tunnelIP netip.Addr
	mtu      uint16
}

// context 처리
func (c *Client) handshake(conn *net.UDPConn) (handshakeResult, error) {
	conn.SetWriteDeadline(time.Now().Add(defaultHandshakeTimeout))
	defer conn.SetWriteDeadline(time.Time{})

	m := &protocol.Message{
		Type: protocol.MessageTypeAloha,
	}
	packet, err := protocol.EncodePacket(m, c.cfg.AuthKey)
	if err != nil {
		return handshakeResult{}, err
	}
	_, err = conn.Write(packet)
	if err != nil {
		return handshakeResult{}, err
	}
	log.Printf("[handshake] sent ALOHA to %s", conn.RemoteAddr().String())

	recvBuf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize+protocol.AuthTagLen)
	n, err := conn.Read(recvBuf)
	if err != nil {
		return handshakeResult{}, err
	}

	message, err := protocol.DecodePacket(recvBuf[:n], c.cfg.AuthKey)
	if err != nil {
		return handshakeResult{}, err
	}
	if message.Type != protocol.MessageTypeWelcome {
		return handshakeResult{}, fmt.Errorf("unexpected message type: expected=%d actual=%d", protocol.MessageTypeWelcome, message.Type)
	}

	welcomePayload, err := protocol.DecodeWelcomePayload(message.Payload)
	if err != nil {
		return handshakeResult{}, err
	}

	result := handshakeResult{
		peerID:   message.PeerID,
		tunnelIP: welcomePayload.TunnelIP,
		mtu:      welcomePayload.MTU,
	}
	log.Printf("[handshake] received WELCOME peer_id=%d tunnel_ip=%s mtu=%d", result.peerID, result.tunnelIP.String(), result.mtu)

	return result, nil
}
