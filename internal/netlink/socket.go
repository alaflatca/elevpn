package netlink

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	nfnlVersion   = 0
	nftaBitwiseOp = 6

	nfIPPriNATSrc int32 = 100 // NF_IP_PRI_NAT_SRC
)

func openNetlink(proto int) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, proto)
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}
	return fd, nil
}

// 데이터 송신 (TLV)
// Netlink Header
// Netfilter Header
// Attributes

// 데이터 수신
// NLMSG_ERROR 데이터 구조
// Netlink Header  (16 byte)
//     [Length    (4 bytes)] *응답 메시지 전체 길이
//     [type      (2 bytes)] *항상 2(NLMSG_ERROR)
//     [Flags     (2 bytes)] *응답 관련 플래그
//     [Sequence  (4 bytes)] *내가 보냈던 요청의 일련번호가 그대로 돌아옴
//     [PortID    (4 bytes)] *내 프로세스 ID
// Error Payload (netlink header의 type이 NLMSG_ERROR 이어야만 아래와 같은 구조)
//     [Errno     (4 bytes)] *0이면 성공, 음수면 실패
//     [Original Header (16 bytes)] *요청했을때 헤더를 돌려줌 (발신자 확인 가능 및 이 요청에 대한 답장이라는걸 확인 시켜주는 용도)

func recvAcks(fd int, want ...uint32) error {
	expected := make(map[uint32]bool, len(want))
	for _, seq := range want {
		expected[seq] = false
	}

	buf := make([]byte, 64*1024)
	got := 0

	tv := unix.Timeval{
		Sec: 5,
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt: %v", err)
	}

	for got < len(expected) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return fmt.Errorf("netlink response timeout(커널 응답 X)")
			}
			return fmt.Errorf("recv netlink: %w", err)
		}

		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			msgLen := int(binary.NativeEndian.Uint32(buf[off : off+4]))
			if msgLen < unix.NLMSG_HDRLEN || off+align4(msgLen) > n {
				return fmt.Errorf("invalid netlink reply")
			}

			msgType := binary.NativeEndian.Uint16(buf[off+4 : off+6])
			msgSeq := binary.NativeEndian.Uint32(buf[off+8 : off+12])

			// 성공/실패 ==> NLMSG_ERROR 타입, 그 안에 errno를 확인해야됨
			if msgType == unix.NLMSG_ERROR {
				if msgLen < unix.NLMSG_HDRLEN+4 {
					// NLMSG_ERROR 메시지라면 최소한 errno 4바이트는 있어야 하므로,
					// 그보다 짧으면 깨진 응답으로 봅니다.
					return fmt.Errorf("short NLMSG_ERROR")
				}
				errno := int32(binary.NativeEndian.Uint32(buf[off+16 : off+20]))
				if errno != 0 {
					return fmt.Errorf("netlink errno=%d (%v) seq=%d msgType=%d msgLen=%d", -errno, unix.Errno(-errno), msgSeq, msgType, msgLen)
				}
				if done, ok := expected[msgSeq]; ok && !done {
					expected[msgSeq] = true
					got++
				}
			}

			off += align4(msgLen)
		}
	}
	return nil
}

// Netlink Header (16 + Payload)
// [ Length		(4 byte)]
// [ Type 		(2 byte)]
// [ Flags		(2 byte)]
// [ Sequence	(4 byte)]
// [ Port ID 	(4 byte)]
// [ Payload 	(가변 길이)]

// 역할: 공통 Netlink 헤더를 붙여 최종적인 **'전송 가능한 패킷'**을 완성합니다.
// seq: 일련번호입니다. 내가 보낸 요청과 커널의 응답을 매칭할 때 씁니다.
// msgType: 배치 시작(Batch Begin)인지 종료(Batch End)인지 결정합니다.
// flags: 요청(REQUEST)이며 응답(ACK)을 꼭 달라는 옵션을 설정합니다.
// body: 위에서 만든 nfgen 데이터가 이 몸체(Body)로 들어갑니다.
func nlMsg(seq uint32, msgType uint16, flags uint16, payload []byte) []byte {
	h := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(h[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(h[4:6], msgType)
	binary.NativeEndian.PutUint16(h[6:8], flags)
	binary.NativeEndian.PutUint32(h[8:12], seq)
	binary.NativeEndian.PutUint32(h[12:16], 0)
	copy(h[unix.NLMSG_HDRLEN:], payload)

	return h
}

// Netlink가 데이터를 담는 방식 TLV (TYPE-LENGTH-VALUE)
// Netlink Attribute Format
// [ length 	( 2 byte ) ]
// [ type 		( 2 byte ) ]
// [ payload	( 가변 길이 ) ]
// [ padding 	(필요하다면 padding 사용)] attr 포맷은 4의 배수로 만들어서 전달해야됨
// ===> [length][type][payload][padding]
func putAttr(buf []byte, typ uint16, payload []byte) []byte {
	length := 4 + len(payload)

	header := make([]byte, 4)
	binary.NativeEndian.PutUint16(header[0:2], uint16(length))
	binary.NativeEndian.PutUint16(header[2:4], typ)

	buf = append(buf, header...)
	buf = append(buf, payload...)

	pad := align4(length) - length
	if pad > 0 { // 패딩이 0보다 크다는건 길이가 4의 배수가 아니기 때문에, pad 길이만큼 패딩 필요
		buf = append(buf, make([]byte, pad)...)
	}

	return buf
}

/* Attr과 NestAttr의 구조 (버퍼에 순차적으로 나열되어있음,attr 구조로)
d = []byte[
  Attr(length, type, payload, padding),
  NestAttr(lengh, type|nested, payload(type:data_value, payload:Attr),padding)
  NestAttr(...)
  Attr,
]
*/

func putNestAttr(buf []byte, typ uint16, nested []byte) []byte {
	return putAttr(buf, typ|unix.NLA_F_NESTED, nested)
}

func dataValue(v []byte) []byte {
	var b []byte
	b = putAttr(b, unix.NFTA_DATA_VALUE, v)
	return b
}

// 매개변수 n을 4의 배수로 조정하는 함수
// 4의 배수라면 아무 변화없이 리턴
// 4의 배수가 아니라면 4의 배수로 올림 (9 -> 12)
// 1001(9) --> 1100(12, n+3) --> 1100(12, &^3)
func align4(n int) int {
	return (n + 3) &^ 3
}

// 끝을 알리는 신호(0)을 포함해야함
func zstr(s string) []byte {
	return append([]byte(s), 0)
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func beS32(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}
