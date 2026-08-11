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

	clientSequence uint64
	serverSequence uint64
}

// context 처리
func (c *Client) handshake(conn *net.UDPConn) (handshakeResult, error) {
	conn.SetWriteDeadline(time.Now().Add(defaultHandshakeTimeout))
	defer conn.SetWriteDeadline(time.Time{})

	alohaSequence := uint64(1)

	m := &protocol.Message{
		Type:     protocol.MessageTypeAloha,
		Sequence: alohaSequence,
	}
	packet, err := c.cipher.EncodePacket(m, protocol.DirectionClientToServer)
	if err != nil {
		return handshakeResult{}, err
	}
	_, err = conn.Write(packet)
	if err != nil {
		return handshakeResult{}, err
	}
	log.Printf("[handshake] sent ALOHA to %s", conn.RemoteAddr().String())

	recvBuf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize+protocol.AEADTagLen)
	n, err := conn.Read(recvBuf)
	if err != nil {
		return handshakeResult{}, err
	}

	message, err := c.cipher.DecodePacket(recvBuf[:n], protocol.DirectionServerToClient)
	if err != nil {
		return handshakeResult{}, err
	}
	if message.Type != protocol.MessageTypeWelcome {
		return handshakeResult{}, fmt.Errorf("unexpected message type: expected=%d actual=%d", protocol.MessageTypeWelcome, message.Type)
	}

	expectedWelcomeSequence := uint64(1)
	if message.Sequence != expectedWelcomeSequence {
		return handshakeResult{}, fmt.Errorf("invalid welcome sequence: expected=%d actual=%d", expectedWelcomeSequence, message.Sequence)
	}

	welcomePayload, err := protocol.DecodeWelcomePayload(message.Payload)
	if err != nil {
		return handshakeResult{}, err
	}

	result := handshakeResult{
		peerID:   message.PeerID,
		tunnelIP: welcomePayload.TunnelIP,
		mtu:      welcomePayload.MTU,

		clientSequence: alohaSequence,
		serverSequence: message.Sequence,
	}
	log.Printf("[handshake] received WELCOME peer_id=%d tunnel_ip=%s mtu=%d", result.peerID, result.tunnelIP.String(), result.mtu)

	return result, nil
}
