package vpn

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	// nfnetlink / nftables
	nfnlSubsysNftables = 10
	nfnlMsgBatchBegin  = unix.NLMSG_MIN_TYPE
	nfnlMsgBatchEnd    = unix.NLMSG_MIN_TYPE + 1
	nfnlVersion        = 0

	// family / hook / priority
	nfprotoIPv4       = 2   // NFPROTO_IPV4
	nfInetPostRouting = 4   // NF_INET_POST_ROUTING
	nfIPPriNatSrc     = 100 // NF_IP_PRI_NAT_SRC

	// nft message types
	nftMsgNewTable = 0
	nftMsgNewChain = 3
	nftMsgNewRule  = 6

	// table attrs
	nftaTableName = 1

	// chain attrs
	nftaChainTable = 1
	nftaChainName  = 3
	nftaChainHook  = 4
	nftaChainType  = 7

	// hook attrs
	nftaHookHooknum  = 1
	nftaHookPriority = 2

	// rule attrs
	nftaRuleTable       = 1
	nftaRuleChain       = 2
	nftaRuleExpressions = 4

	// expr list / expr attrs
	nftaListElem = 1
	nftaExprName = 1
	nftaExprData = 2

	// data attrs
	nftaDataValue = 1

	// payload expr attrs
	nftaPayloadDreg   = 1
	nftaPayloadBase   = 2
	nftaPayloadOffset = 3
	nftaPayloadLen    = 4

	// bitwise expr attrs
	nftaBitwiseSreg = 1
	nftaBitwiseDreg = 2
	nftaBitwiseLen  = 3
	nftaBitwiseMask = 4
	nftaBitwiseXor  = 5
	nftaBitwiseOp   = 6

	// cmp expr attrs
	nftaCmpSreg = 1
	nftaCmpOp   = 2
	nftaCmpData = 3

	// meta expr attrs
	nftaMetaDreg = 1
	nftaMetaKey  = 2

	// registers
	nftReg1 = 1
	nftReg2 = 2

	// payload base
	nftPayloadNetworkHeader = 1

	// bitwise / cmp ops
	nftBitwiseBool = 0
	nftCmpEq       = 0

	// meta key
	nftMetaOifname = 7

	nlaFNested = 1 << 15
)

// 데이터 송신 (TLV)
// Netlink Header
// Netfilter Header
// Attributes

// 데이터 수신
// NLMSG_ERROR 데이터 구조
// Netlink Header  (16 byte)
// Error Code	   (4  byte)
// Original Header (16 byte) 내가 보냈던 요청 헤더 그대로 돌려줌 (발신자 확인용)
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

// Netfilter 통신의 위한 데이터 계층
//  1. NetLink Header 		# 커널이 "이 데이터 덩어리는 어디까지인가?"를 파악하는 용도 (16바이트)
//  2. Netfilter Header		# 커널의 Netfilter 모듈이 "IPv4인가, IPv6인가?"를 파악하는 용도 (4바이트)
//  3. Payload(Attributes)	# 실제 "테이블 이름은 'vpn_table'이다"(체인, 룰 포함) 같은 상세 정보 (가변 길이)
//
// ==============================
// 1. [Batch Begin] Netlink Hdr + NetFilter Hdr
// 2. [New Table] 	Netlink Hdr + NetFilter Hdr + Table Attributes (Payload)
// 3. [New Chain] 	Netlink Hdr + NetFilter Hdr + Chain Attributes (Payload)
// 4. [New Rule]	Netlink Hdr + NetFilter Hdr + Rule  Attributes (Payload)
// 5. [Batch End] 	Netlink Hdr + NetFilter Hdr
func batchMsg(seq uint32, msgType uint16) []byte {
	body := nfgen(unix.AF_UNSPEC, nfnlSubsysNftables)
	return nlMsg(seq, msgType, unix.NLM_F_REQUEST, body)
}

// NetFilter Header
// 역할: Netfilter 전용 헤더(nfgenmsg)를 생성합니다.
// 내용: [가족(Family), 버전, 리소스ID_고위, 리소스ID_저위] 형태의 4바이트 데이터
// family : 어떤 네트워크 체계 (IPv4, IPv6, UNSPEC(미지정, 작업시작 알림))
//   - AF_INET   : IPv4
//   - AF_INET6  : IPv6
//   - AF_UNSPEC : 작업 시작/종료 신호
//
// nfnlVersion : Netfilter 넷링크 버전 (보통 0)
// res_id : 리소스ID,  나중을 위해 예약된 공간 (보통 0,0)
func nfgen(family byte, resID uint16) []byte {
	b := make([]byte, 4)
	b[0] = family
	b[1] = nfnlVersion
	binary.BigEndian.PutUint16(b[2:4], resID)
	return b
}

// Netlink Header
// [ Length (4 byte)]
// [ Type 	(2 byte)]
// [ Flags	(2 byte)]
// [ Sequence	(4 byte)]
// [ Port ID (4 byte)]
// [ Payload (가변 길이)]

// 역할: 공통 Netlink 헤더를 붙여 최종적인 **'전송 가능한 패킷'**을 완성합니다.
// seq: 일련번호입니다. 내가 보낸 요청과 커널의 응답을 매칭할 때 씁니다.
// msgType: 배치 시작(Batch Begin)인지 종료(Batch End)인지 결정합니다.
// flags: 요청(REQUEST)이며 응답(ACK)을 꼭 달라는 옵션을 설정합니다.
// body: 위에서 만든 nfgen 데이터가 이 몸체(Body)로 들어갑니다.
func nlMsg(seq uint32, msgType uint16, flags uint16, payload []byte) []byte {
	h := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(h[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(h[4:6], msgType)
	binary.NativeEndian.PutUint16(h[6:8], flags)
	binary.NativeEndian.PutUint32(h[8:12], seq)
	binary.NativeEndian.PutUint32(h[12:16], 0)
	return append(h, payload...)
}

// Netlink가 데이터를 담는 방식 TLV (TYPE-LENGTH-VALUE)
// Netlink Attribute Format
// [ length 	( 2 byte ) ]
// [ type 		( 2 byte ) ]
// [ payload	( 가변 길이 ) ]
// [ padding 	(필요하다면 padding 사용)] attr 포맷은 4의 배수로 만들어서 전달해야됨
func putAttr(buf []byte, typ uint16, payload []byte) []byte {
	length := 4 + len(payload)

	header := make([]byte, 4)
	binary.NativeEndian.PutUint16(header[0:2], uint16(length))
	binary.NativeEndian.PutUint16(header[2:4], typ)

	buf = append(buf, header...)
	buf = append(buf, payload...)

	pad := align4(length) - length
	if pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}

	return buf
}

func putNestAttr(buf []byte, typ uint16, nested []byte) []byte {
	return putAttr(buf, typ|nlaFNested, nested)
}

func dataValue(v []byte) []byte {
	var b []byte
	b = putAttr(b, nftaDataValue, v)
	return b
}

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
