package protocol

import (
	"errors"
	"fmt"
)

const alohaPacketPrefixLen = MessageHeaderLen + HandshakeRandomLen

func (c *Cipher) EncodeAlohaPacket(message *Message, clientRandom HandshakeRandom) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("handshake cipher is nil")
	}
	if message == nil {
		return nil, errors.New("aloha message is nil")
	}
	if message.Type != MessageTypeAloha {
		return nil, fmt.Errorf("invalid aloha message type: expected=%d actual=%d", MessageTypeAloha, message.Type)
	}

	plainPacket, err := Encode(message)
	if err != nil {
		return nil, fmt.Errorf("failed to encode aloha message: %w", err)
	}

	header := plainPacket[:MessageHeaderLen]
	payload := plainPacket[MessageHeaderLen:]

	aad := make([]byte, MessageHeaderLen+HandshakeRandomLen)
	copy(aad[:MessageHeaderLen], header)
	copy(aad[MessageHeaderLen:], clientRandom[:])

	sealedPayload, err := c.SealPayload(DirectionClientToServer, message.Sequence, aad, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to seal aloha payload: %w", err)
	}

	packet := make([]byte, len(aad)+len(sealedPayload))
	copy(packet[:len(aad)], aad)
	copy(packet[len(aad):], sealedPayload)

	// SealPayload에서 AAD는 암호화되지 않고 결과에도 자동으로 포함되지 않지만, tag 계산에는 참여해.
	// [header 20][clientRandom 16][encrypted payload][AEAD tag 16]
	//  └────────── AAD ─────────┘  └────── sealedPayload ───────┘

	return packet, nil
}

func (cs *CipherSuite) DecodeAlohaPacket(packet []byte) (*Message, HandshakeRandom, error) {
	minPacketLen := alohaPacketPrefixLen + AEADTagLen

	if len(packet) < minPacketLen {
		return nil, HandshakeRandom{}, fmt.Errorf("invalid aloha packet length: expected>=%d actual=%d", minPacketLen, len(packet))
	}

	header, err := PeekHeader(packet)
	if err != nil {
		return nil, HandshakeRandom{}, fmt.Errorf("failed to read aloha header: %w", err)
	}
	if header.Version != ProtocolVersion {
		return nil, HandshakeRandom{}, fmt.Errorf("invalid aloha protocol version: expected=%d actual=%d", ProtocolVersion, header.Version)
	}
	if header.Type != MessageTypeAloha {
		return nil, HandshakeRandom{}, fmt.Errorf("invalid aloha message type: expected=%d actual=%d", MessageTypeAloha, header.Type)
	}
	if header.PeerID != 0 {
		return nil, HandshakeRandom{}, fmt.Errorf("aloha peer id must be zero: actual=%d", header.PeerID)
	}
	if header.Sequence == 0 {
		return nil, HandshakeRandom{}, errors.New("aloha sequence must be greater than zero")
	}

	var clientRandom HandshakeRandom
	copy(clientRandom[:], packet[MessageHeaderLen:alohaPacketPrefixLen])

	handshakeCipher, err := cs.NewHandshakeCipher(clientRandom)
	if err != nil {
		return nil, HandshakeRandom{}, fmt.Errorf("failed to create handshake cipher: %w", err)
	}

	aad := packet[:alohaPacketPrefixLen]
	sealedPayload := packet[alohaPacketPrefixLen:]

	plainPayload, err := handshakeCipher.OpenPayload(DirectionClientToServer, header.Sequence, aad, sealedPayload)
	if err != nil {
		return nil, HandshakeRandom{}, fmt.Errorf("failed to authenticate aloha packet: %w", err)
	}

	plainPacket := make([]byte, MessageHeaderLen+len(plainPayload))
	copy(plainPacket[:MessageHeaderLen], packet[:MessageHeaderLen])
	copy(plainPacket[MessageHeaderLen:], plainPayload)

	message, err := Decode(plainPacket)
	if err != nil {
		return nil, HandshakeRandom{}, fmt.Errorf("failed to decode aloha message: %w", err)
	}

	return message, clientRandom, nil
}
