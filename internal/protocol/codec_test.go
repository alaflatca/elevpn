package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestPeerCipherPacketRoundTrip(t *testing.T) {
	psk := []byte("test-secret")
	peerID := uint64(1)

	clientRandom := HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	serverRandom := HandshakeRandom{
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}

	clientSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create client cipher suite: %v", err)
	}

	serverSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create server cipher suite: %v", err)
	}

	clientCipher, err := clientSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create client peer cipher: %v", err)
	}

	serverCipher, err := serverSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create server peer cipher: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeData,
			PeerID:   peerID,
			Sequence: 2,
		},
		Payload: []byte("hello elevpn"),
	}

	packet, err := clientCipher.EncodePacket(want, DirectionClientToServer)
	if err != nil {
		t.Fatalf("failed to encode packet: %v", err)
	}

	got, err := serverCipher.DecodePacket(packet, DirectionClientToServer)
	if err != nil {
		t.Fatalf("failed to decode packet: %v", err)
	}

	if got.Header != want.Header {
		t.Errorf("header mismatch: expected=%+v actual=%+v", want.Header, got.Header)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("payload mismatch: expected=%q actual=%q", want.Payload, got.Payload)
	}
}

func TestPeerCipherPacketRejectsWrongPSK(t *testing.T) {
	clientPSK := []byte("test-sec")
	serverPSK := []byte("test-secret")

	peerID := uint64(1)

	clientRandom := HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	serverRandom := HandshakeRandom{
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}

	clientSuite, err := NewCipherSuite(clientPSK)
	if err != nil {
		t.Fatalf("failed to create client cipher suite: %v", err)
	}

	serverSuite, err := NewCipherSuite(serverPSK)
	if err != nil {
		t.Fatalf("failed to create server cipher suite: %v", err)
	}

	clientCipher, err := clientSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create client peer cipher: %v", err)
	}

	serverCipher, err := serverSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create server peer cipher: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeData,
			PeerID:   peerID,
			Sequence: 2,
		},
		Payload: []byte("hello elevpn"),
	}

	packet, err := clientCipher.EncodePacket(want, DirectionClientToServer)
	if err != nil {
		t.Fatalf("failed to encode packet: %v", err)
	}

	_, err = serverCipher.DecodePacket(packet, DirectionClientToServer)
	if err == nil {
		t.Fatal("expected authentication failure, but decode succeeded")
	}

	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed, got: %v", err)
	}
}

func TestPeerCipherPacketRejectsTampering(t *testing.T) {
	psk := []byte("test-secret")
	peerID := uint64(1)

	clientRandom := HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	serverRandom := HandshakeRandom{
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}

	clientSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create client cipher suite: %v", err)
	}

	serverSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create server cipher suite: %v", err)
	}

	clientCipher, err := clientSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create client peer cipher: %v", err)
	}

	serverCipher, err := serverSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create server peer cipher: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeData,
			PeerID:   peerID,
			Sequence: 2,
		},
		Payload: []byte("hello elevpn"),
	}

	packet, err := clientCipher.EncodePacket(want, DirectionClientToServer)
	if err != nil {
		t.Fatalf("failed to encode packet: %v", err)
	}
	packet[MessageHeaderLen] ^= 0x01

	_, err = serverCipher.DecodePacket(packet, DirectionClientToServer)
	if err == nil {
		t.Fatal("expected tampered packet to fail authentication, but decode succeeded")
	}

	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed for tampered packet, got: %v", err)
	}
}

func TestPeerCipherPacketRejectsWrongDirection(t *testing.T) {
	psk := []byte("test-secret")
	peerID := uint64(1)

	clientRandom := HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}
	serverRandom := HandshakeRandom{
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}

	clientSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create client cipher suite: %v", err)
	}

	serverSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create server cipher suite: %v", err)
	}

	clientCipher, err := clientSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create client peer cipher: %v", err)
	}

	serverCipher, err := serverSuite.NewPeerCipher(peerID, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create server peer cipher: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeData,
			PeerID:   peerID,
			Sequence: 2,
		},
		Payload: []byte("hello elevpn"),
	}

	packet, err := clientCipher.EncodePacket(want, DirectionClientToServer)
	if err != nil {
		t.Fatalf("failed to encode packet: %v", err)
	}

	_, err = serverCipher.DecodePacket(packet, DirectionServerToClient)
	if err == nil {
		t.Fatal("expected wrong direction to fail authentication, but decode succeeded")
	}

	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed for wrong direction, got: %v", err)
	}
}
