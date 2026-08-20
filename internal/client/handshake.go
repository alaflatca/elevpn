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

	cipher *protocol.Cipher

	clientSequence     uint64
	serverReplayWindow protocol.ReplayWindow
}

// context 처리
func (c *Client) handshake(conn *net.UDPConn) (handshakeResult, error) {
	conn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	m := &protocol.Message{
		Header: protocol.Header{
			Type:     protocol.MessageTypeAloha,
			Sequence: 1,
		},
	}

	clientRandom, err := protocol.GenerateHandshakeRandom()
	if err != nil {
		return handshakeResult{}, err
	}

	alohaCipher, err := c.cipherSuite.NewAlohaCipher(clientRandom)
	if err != nil {
		return handshakeResult{}, err
	}

	packet, err := alohaCipher.EncodeAlohaPacket(m, clientRandom)
	if err != nil {
		return handshakeResult{}, err
	}
	_, err = conn.Write(packet)
	if err != nil {
		return handshakeResult{}, err
	}
	log.Printf("[handshake] sent ALOHA to %s", conn.RemoteAddr().String())

	recvBuf := make([]byte, protocol.MessageHeaderLen+protocol.HandshakeRandomLen+protocol.MaxPayloadSize+protocol.AEADTagLen)
	n, err := conn.Read(recvBuf)
	if err != nil {
		return handshakeResult{}, err
	}

	message, serverRandom, err := c.cipherSuite.DecodeWelcomePacket(recvBuf[:n], clientRandom)
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

	var serverReplayWindow protocol.ReplayWindow
	if err := serverReplayWindow.Accept(message.Sequence); err != nil {
		return handshakeResult{}, fmt.Errorf("invalid replay window sequence=%d: %w", message.Sequence, err)
	}

	welcomePayload, err := protocol.DecodeWelcomePayload(message.Payload)
	if err != nil {
		return handshakeResult{}, err
	}

	peerCipher, err := c.cipherSuite.NewPeerCipher(message.PeerID, clientRandom, serverRandom)
	if err != nil {
		return handshakeResult{}, err
	}

	result := handshakeResult{
		peerID:   message.PeerID,
		tunnelIP: welcomePayload.TunnelIP,
		mtu:      welcomePayload.MTU,

		cipher: peerCipher,

		clientSequence:     1,
		serverReplayWindow: serverReplayWindow,
	}
	log.Printf("[handshake] received WELCOME peer_id=%d tunnel_ip=%s mtu=%d", result.peerID, result.tunnelIP.String(), result.mtu)

	return result, nil
}
