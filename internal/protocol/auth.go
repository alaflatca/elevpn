package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var ErrAuthenticationFailed = errors.New("authentication failed")

func hmacSHA256(psk []byte, packet []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(packet)
	return mac.Sum(nil)
}

func AppendAuthTag(psk []byte, packet []byte) []byte {
	tag := hmacSHA256(psk, packet)
	packetWithTag := append(packet, tag...)
	return packetWithTag
}

func VerifyAuthTag(psk []byte, packetWithTag []byte) ([]byte, bool) {
	if len(packetWithTag) < MessageHeaderLen+AuthTagLen {
		return nil, false
	}
	packetEnd := len(packetWithTag) - AuthTagLen
	packet := packetWithTag[:packetEnd]

	receivedTag := packetWithTag[packetEnd:]
	expectedTag := hmacSHA256(psk, packet)
	if !hmac.Equal(receivedTag, expectedTag) {
		return nil, false
	}

	return packet, true
}
