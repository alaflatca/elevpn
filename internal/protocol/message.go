package protocol

type MessageType uint8

func (m MessageType) valid() bool {
	switch m {
	case MessageTypeAloha, MessageTypeWelcome,
		MessageTypeData, MessageTypeKeepalive:
		return true
	default:
		return false
	}
}

const (
	MessageTypeAloha     = 1
	MessageTypeWelcome   = 2
	MessageTypeData      = 3
	MessageTypeKeepalive = 4

	ProtocolVersion = 1

	// [version 1][type 1][flags 1][reserved 1][peer ID 8][sequence 8]
	MessageHeaderLen = 20
	AEADTagLen       = 16

	// TUN MTU = outer MTU - outer IPv4 - UDP - elevpn header - AEAD tag
	DefaultOuterMTU    = 1500
	OuterIPv4HeaderLen = 20
	UDPHeaderLen       = 8

	MaxPayloadSize = DefaultOuterMTU -
		OuterIPv4HeaderLen -
		UDPHeaderLen -
		MessageHeaderLen -
		AEADTagLen

	DefaultTunnelMTU uint16 = MaxPayloadSize
)

type Header struct {
	Version  uint8
	Type     MessageType
	Flags    uint8
	Reserved uint8
	PeerID   uint64
	Sequence uint64
}

type Message struct {
	Header
	Payload []byte
}
