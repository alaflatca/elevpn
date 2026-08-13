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

	MessageHeaderLen = 20
	/* Message Header 20 byte
	protocolversion 1byte
	type 			1byte
	flags 			1byte
	reserved 		1byte
	peerID			8byte
	sequence 		8byte
	*/

	MaxPayloadSize          = 1460
	DefaultTunnelMTU uint16 = 1460

	AEADTagLen = 16
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
