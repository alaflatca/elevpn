package protocol

import (
	"net/netip"
	"testing"
)

func TestAlohaPacketRoundTrip(t *testing.T) {
	psk := []byte("test-secret")
	clientRandom := HandshakeRandom{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16,
	}

	clientSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create client cipher suite: %v", err)
	}
	serverSuite, err := NewCipherSuite(psk)
	if err != nil {
		t.Fatalf("failed to create server cipher suite: %v", err)
	}

	clientCipher, err := clientSuite.NewAlohaCipher(clientRandom)
	if err != nil {
		t.Fatalf("failed to create aloha cipher: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeAloha,
			PeerID:   0,
			Sequence: 1,
		},
	}

	packet, err := clientCipher.EncodeAlohaPacket(want, clientRandom)
	if err != nil {
		t.Fatalf("failed to encode aloha: %v", err)
	}

	got, gotClientRandom, err := serverSuite.DecodeAlohaPacket(packet)
	if err != nil {
		t.Fatalf("failed to decode aloha: %v", err)
	}

	if clientRandom != gotClientRandom {
		t.Errorf("client random mismatch: expected=%v actual=%v", clientRandom, gotClientRandom)
	}

	if got.Header != want.Header {
		t.Errorf("header mismatch: expected=%+v actual=%+v", want.Header, got.Header)
	}
}

func TestWelcomePacketRoundTrip(t *testing.T) {
	psk := []byte("test-secret")
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

	welcomeCipher, err := serverSuite.NewWelcomeCipher(clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("failed to create welcome cipher: %v", err)
	}

	welcomePayload := WelcomePayload{
		TunnelIP: netip.MustParseAddr("10.77.0.2"),
		MTU:      DefaultTunnelMTU,
	}

	welcomePayloadBytes, err := EncodeWelcomePayload(welcomePayload)
	if err != nil {
		t.Fatalf("failed to encode welcome payload: %v", err)
	}

	want := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     MessageTypeWelcome,
			PeerID:   1,
			Sequence: 1,
		},
		Payload: welcomePayloadBytes,
	}

	packet, err := welcomeCipher.EncodeWelcomePacket(want, serverRandom)
	if err != nil {
		t.Fatalf("failed to encode welcome packet: %v", err)
	}

	got, gotServerRandom, err := clientSuite.DecodeWelcomePacket(packet, clientRandom)
	if err != nil {
		t.Fatalf("failed to decode welcome packet: %v", err)
	}
	if serverRandom != gotServerRandom {
		t.Errorf("server random mismatch: expected=%v actual=%v", serverRandom, gotServerRandom)
	}
	if got.Header != want.Header {
		t.Errorf("header mismatch: expected=%+v, actual=%+v", want.Header, got.Header)
	}

	gotWelcomePayload, err := DecodeWelcomePayload(got.Payload)
	if err != nil {
		t.Fatalf("failed to decode welcome payload: %v", err)
	}

	if gotWelcomePayload != welcomePayload {
		t.Errorf("payload mismatch: expected=%+v actual=%+v", welcomePayload, gotWelcomePayload)
	}
}
