package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	WelcomePayloadLen = 6
)

type WelcomePayload struct {
	TunnelIP netip.Addr
	MTU      uint16
}

func EncodeWelcomePayload(payload WelcomePayload) ([]byte, error) {
	var packet [WelcomePayloadLen]byte

	if !payload.TunnelIP.Is4() {
		return nil, fmt.Errorf("welcome payload tunnel ip must be IPv4: %s", payload.TunnelIP)
	}
	if payload.MTU == 0 {
		return nil, errors.New("welcome payload mtu must be greater than 0")
	}

	tunnelIP := payload.TunnelIP.As4()
	copy(packet[0:4], tunnelIP[:])
	binary.BigEndian.PutUint16(packet[4:6], payload.MTU)

	return packet[:], nil
}

func DecodeWelcomePayload(buf []byte) (WelcomePayload, error) {
	if len(buf) != WelcomePayloadLen {
		return WelcomePayload{}, fmt.Errorf("invalid welcome payload length: expected=%d actual=%d", WelcomePayloadLen, len(buf))
	}

	payload := WelcomePayload{}

	var ip4 [4]byte
	copy(ip4[:], buf[0:4])
	payload.TunnelIP = netip.AddrFrom4(ip4)
	payload.MTU = binary.BigEndian.Uint16(buf[4:6])

	return payload, nil
}
