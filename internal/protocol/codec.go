package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
[header 12 bytes][payload 가변 bytes][hmac tag 32 bytes]

[header] 12 bytes
protocolversion 1byte
type 			1byte
flags 			1byte
reserved 		1byte
peerID			8byte
[payload] 가변 bytes
[hmac tag] 32 bytes
*/

// 네트워크 프로토콜이면 BigEndian을 사용하는게 일반 적
// 전통적으로 네트워크 바이트 오더가 BigEndian이기 떄문
func Encode(m *Message) ([]byte, error) {
	if m == nil {
		return nil, errors.New("message is nil")
	}
	if !m.Type.valid() {
		return nil, fmt.Errorf("invalid message type: %d", m.Type)
	}
	if len(m.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("invalid payload size(max payload size: %d): %d", MaxPayloadSize, len(m.Payload))
	}

	buf := make([]byte, MessageHeaderLen+len(m.Payload))
	buf[0] = ProtocolVersion
	buf[1] = byte(m.Type)
	buf[2] = m.Flags
	buf[3] = m.Reserved
	binary.BigEndian.PutUint64(buf[4:12], m.PeerID)
	binary.BigEndian.PutUint64(buf[12:MessageHeaderLen], m.Sequence)
	copy(buf[MessageHeaderLen:], m.Payload)

	return buf, nil
}

func Decode(buf []byte) (*Message, error) {
	if len(buf) < MessageHeaderLen {
		return nil, fmt.Errorf("invalid message header len: %d", len(buf))
	}

	version := buf[0]
	messageType := MessageType(buf[1])
	flags := buf[2]
	reserved := buf[3]
	peerID := binary.BigEndian.Uint64(buf[4:12])
	sequence := binary.BigEndian.Uint64(buf[12:MessageHeaderLen])

	payloadLen := len(buf) - MessageHeaderLen
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload size exceeds maximum: max=%d actual=%d", MaxPayloadSize, payloadLen)
	}
	if version != ProtocolVersion {
		return nil, fmt.Errorf("invalid protocol version(%d != %d)", version, ProtocolVersion)
	}
	if !messageType.valid() {
		return nil, fmt.Errorf("unknown message type=%d", messageType)
	}

	payload := make([]byte, payloadLen)
	copy(payload, buf[MessageHeaderLen:])

	return &Message{
		Version:  version,
		Type:     messageType,
		Flags:    flags,
		Reserved: reserved,
		PeerID:   peerID,
		Sequence: sequence,
		Payload:  payload,
	}, nil
}

func EncodePacket(message *Message, psk []byte) ([]byte, error) {
	packet, err := Encode(message)
	if err != nil {
		return nil, err
	}
	return AppendAuthTag(psk, packet), nil
}

func DecodePacket(buf []byte, psk []byte) (*Message, error) {
	packet, ok := VerifyAuthTag(psk, buf)
	if !ok {
		return nil, fmt.Errorf("failed to verify auth tag: %w", ErrAuthenticationFailed)
	}

	message, err := Decode(packet)
	if err != nil {
		return nil, err
	}

	return message, nil
}

/*
[outer IP header]  # 20 bytes
[outer UDP header] # 8 bytes
[VPN header]	   # 12 bytes
[inner IP packet]

outer IP header
  실제 인터넷에서 서버까지 가기 위한 IP 헤더
  client public/private IP -> server public IP

outer UDP header
  네 VPN 프로그램끼리 통신하기 위한 UDP 헤더
  client UDP port -> server UDP port 9010

VPN header
  네가 직접 만드는 프로토콜 헤더
  ALOHA/WELCOME/DATA/KEEPALIVE, peer id 등

inner IP packet
  TUN에서 읽은 원래 패킷
  VPN을 통해 보내고 싶은 실제 트래픽

inner IP packet 안은 다시 이렇게 나뉘어.
  [inner IP header]
  [transport header]
  [application payload]

*TCP 예시
[outer IP][outer UDP][VPN][inner IP][inner TCP][HTTP/TLS data]

*UDP 예시
[outer IP][outer UDP][VPN][inner IP][inner UDP][DNS data]

*ICMP 예시
[outer IP][outer UDP][VPN][inner IP][ICMP][ping data]

*/
