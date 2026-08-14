package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
[header 20bytes][payload 가변 bytes][aead tag 16bytes]

[header] 20 bytes
protocolversion 1 byte
type 			1 byte
flags 			1 byte
reserved 		1 byte
peerID			8 byte
sequence		8 byte

[payload] 가변 bytes
[aead tag] 16 bytes
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

	header, err := PeekHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to peek header: %w", err)
	}

	payloadLen := len(buf) - MessageHeaderLen
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload size exceeds maximum: max=%d actual=%d", MaxPayloadSize, payloadLen)
	}
	if header.Version != ProtocolVersion {
		return nil, fmt.Errorf("invalid protocol version(%d != %d)", header.Version, ProtocolVersion)
	}
	if !header.Type.valid() {
		return nil, fmt.Errorf("unknown message type=%d", header.Type)
	}

	payload := make([]byte, payloadLen)
	copy(payload, buf[MessageHeaderLen:])

	return &Message{
		Header:  header,
		Payload: payload,
	}, nil
}

func (c *Cipher) EncodePacket(message *Message, direction Direction) ([]byte, error) {
	packet, err := Encode(message)
	if err != nil {
		return nil, err
	}

	header := packet[:MessageHeaderLen]
	payload := packet[MessageHeaderLen:]

	sealedPayload, err := c.SealPayload(direction, message.Sequence, header, payload)
	if err != nil {
		return nil, err
	}

	sealedPacket := make([]byte, MessageHeaderLen+len(sealedPayload))
	copy(sealedPacket[:MessageHeaderLen], header)
	copy(sealedPacket[MessageHeaderLen:], sealedPayload)

	return sealedPacket, nil
}

func (c *Cipher) DecodePacket(buf []byte, direction Direction) (*Message, error) {
	if len(buf) < MessageHeaderLen {
		return nil, fmt.Errorf("invalid encrypted packet header length: actual=%d", len(buf))
	}

	header := buf[:MessageHeaderLen]
	sealedPayload := buf[MessageHeaderLen:]

	peekHeader, err := PeekHeader(header)
	if err != nil {
		return nil, fmt.Errorf("failed to peek header: %w", err)
	}

	plainPayload, err := c.OpenPayload(direction, peekHeader.Sequence, header, sealedPayload)
	if err != nil {
		return nil, err
	}

	plainPacket := make([]byte, MessageHeaderLen+len(plainPayload))
	copy(plainPacket[:MessageHeaderLen], header)
	copy(plainPacket[MessageHeaderLen:], plainPayload)

	message, err := Decode(plainPacket)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func PeekHeader(buf []byte) (Header, error) {
	if len(buf) < MessageHeaderLen {
		return Header{}, fmt.Errorf("invalid header length: expected>=%d actual=%d", MessageHeaderLen, len(buf))
	}

	version := buf[0]
	messageType := MessageType(buf[1])
	flags := buf[2]
	reserved := buf[3]
	peerID := binary.BigEndian.Uint64(buf[4:12])
	sequence := binary.BigEndian.Uint64(buf[12:MessageHeaderLen])

	return Header{
		Version:  version,
		Type:     messageType,
		Flags:    flags,
		Reserved: reserved,
		PeerID:   peerID,
		Sequence: sequence,
	}, nil
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
