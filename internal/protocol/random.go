package protocol

import (
	"crypto/rand"
	"fmt"
)

const HandshakeRandomLen = 16

type HandshakeRandom [HandshakeRandomLen]byte

func GenerateHandshakeRandom() (HandshakeRandom, error) {
	var random HandshakeRandom

	if _, err := rand.Read(random[:]); err != nil {
		return HandshakeRandom{}, fmt.Errorf("failed to generate handshake random: %w", err)
	}

	return random, nil
}
