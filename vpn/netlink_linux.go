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
	body := nfgen(unix.AF_UNSPEC)
	return nlMsg(seq, msgType, unix.NLM_F_REQUEST|unix.NLM_F_ACK, body)
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
func nfgen(family byte) []byte {
	return []byte{family, nfnlVersion, 0, 0}
}

// Netlink Header
// 역할: 공통 Netlink 헤더를 붙여 최종적인 **'전송 가능한 패킷'**을 완성합니다.
// seq: 일련번호입니다. 내가 보낸 요청과 커널의 응답을 매칭할 때 씁니다.
// msgType: 배치 시작(Batch Begin)인지 종료(Batch End)인지 결정합니다.
// flags: 요청(REQUEST)이며 응답(ACK)을 꼭 달라는 옵션을 설정합니다.
// body: 위에서 만든 nfgen 데이터가 이 몸체(Body)로 들어갑니다.
func nlMsg(seq uint32, msgType uint16, flags uint16, payload []byte) []byte {
	h := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.AppendUint32(h[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.AppendUint16(h[4:6], msgType)
	binary.NativeEndian.AppendUint16(h[6:8], flags)
	binary.NativeEndian.AppendUint32(h[8:12], seq)
	binary.NativeEndian.AppendUint32(h[12:16], 0)
	return append(h, payload...)
}

func nftMsg(seq uint32, msgType uint16, flags uint16, family byte, attrs []byte) []byte {
	typ := uint16((nfnlSubsysNftables << 8) | int(msgType))
	body := append(nfgen(family), attrs...)
	return nlMsg(seq, typ, flags, body)
}

func buildNewTableMsg(seq uint32, tableName string) []byte {
	var attrs []byte
	attrs = putAttr(attrs, nftaTableName, zstr(tableName))
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
}

func putAttr(buf []byte, typ uint16, payload []byte) []byte {
	length := 4 + len(payload)

	header := make([]byte, 4)
	binary.NativeEndian.AppendUint16(header[0:2], uint16(length))
	binary.NativeEndian.AppendUint16(header[2:4], typ)

	buf = append(buf, header...)
	buf = append(buf, payload...)

}

func zstr(s string) []byte {
	return append([]byte(s), 0)
}
