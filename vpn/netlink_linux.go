package vpn

import (
	"encoding/binary"
	"fmt"
	"net"

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
	binary.NativeEndian.AppendUint32(h[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.AppendUint16(h[4:6], msgType)
	binary.NativeEndian.AppendUint16(h[6:8], flags)
	binary.NativeEndian.AppendUint32(h[8:12], seq)
	binary.NativeEndian.AppendUint32(h[12:16], 0)
	return append(h, payload...)
}

func nftMsg(seq uint32, msgType uint16, flags uint16, family byte, attrs []byte) []byte {
	// msgType이 만약 8이라고 가정한다면
	// before: 0000 1010 0000 0000 --->  after: 0000 1010 0000 1000
	typ := uint16((nfnlSubsysNftables << 8) | int(msgType))
	body := append(nfgen(family), attrs...)
	return nlMsg(seq, typ, flags, body)
}

func buildNewTableMsg(seq uint32, tableName string) []byte {
	var attrs []byte
	attrs = putAttr(attrs, nftaTableName, zstr(tableName))
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	return nftMsg(seq, nftMsgNewTable, flags, nfprotoIPv4, attrs)
}

func buildNewChainMsg(seq uint32, tableName, chainName string) []byte {
	var hookAttrs []byte
	hookAttrs = putAttr(hookAttrs, nftaHookHooknum, be32(nfInetPostRouting))
	hookAttrs = putAttr(hookAttrs, nftaHookPriority, beS32(nfIPPriNatSrc))

	var attrs []byte
	attrs = putAttr(attrs, nftaChainTable, zstr(tableName))
	attrs = putAttr(attrs, nftaChainName, zstr(chainName))
	attrs = putNestAttr(attrs, nftaChainHook, hookAttrs)
	attrs = putAttr(attrs, nftaChainType, zstr("nat"))

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	return nftMsg(seq, nftMsgNewChain, flags, nfprotoIPv4, attrs)
}

func buildNewMasqRuleMsg(seq uint32, tableName, chainName string, ip4, mask4 net.IP, oifName string) []byte {
	var exprs []byte
	exprs = append(exprs, exprPayloadIPv4Saddr()...) // 지나가는 패킷의 출발지 IP 주소를 읽어라
	exprs = append(exprs, exprBitwiseMask(mask4)...) // 위 주소에 서브넷 마스크를 씌워서 네트워크 대역만 남겨라
	exprs = append(exprs, exprCmpIPv4(ip4)...)       // 위 대역이 우리가 허용한 VPN대역이 맞는지 확인해라
	exprs = append(exprs, exprCmpIfName(oifName)...)
	exprs = append(exprs, exprMasq()...)

	var attrs []byte
	attrs = putAttr(attrs, nftaRuleTable, zstr(tableName))
	attrs = putAttr(attrs, nftaRuleChain, zstr(chainName))
	attrs = putAttr(attrs, nftaRuleExpressions, exprs)

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_APPEND)
	return nftMsg(seq, nftMsgNewRule, flags, nfprotoIPv4, attrs)
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
	binary.NativeEndian.AppendUint16(header[0:2], uint16(length))
	binary.NativeEndian.AppendUint16(header[2:4], typ)

	buf = append(buf, header...)
	buf = append(buf, payload...)

	if pad := align4(length); pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}

	return buf
}

func putNestAttr(buf []byte, typ uint16, nested []byte) []byte {
	return putAttr(buf, typ|nlaFNested, nested)
}

func exprPayloadIPv4Saddr() []byte {
	var d []byte
	d = putAttr(d, nftaPayloadDreg, be32(nftReg1))
	d = putAttr(d, nftaPayloadBase, be32(nftPayloadNetworkHeader))
	d = putAttr(d, nftaPayloadOffset, be32(12))
	d = putAttr(d, nftaPayloadLen, be32(4))
	return wrapExpr("payload", d)
}

func exprBitwiseMask(mask net.IP) []byte {
	var d []byte
	d = putAttr(d, nftaBitwiseSreg, be32(nftReg1))
	d = putAttr(d, nftaBitwiseDreg, be32(nftReg1))
	d = putAttr(d, nftaBitwiseLen, be32(4))
	d = putNestAttr(d, nftaBitwiseMask, dataValue(mask.To4()))
	d = putNestAttr(d, nftaBitwiseXor, dataValue([]byte{0, 0, 0, 0}))
	d = putAttr(d, nftaBitwiseOp, be32(nftBitwiseBool))
	return wrapExpr("bitwise", d)
}

func exprCmpIPv4(ip4 net.IP) []byte {
	var d []byte
	d = putAttr(d, nftaCmpSreg, be32(nftReg1))
	d = putAttr(d, nftaCmpOp, be32(nftCmpEq))
	d = putNestAttr(d, nftaCmpData, dataValue(ip4.To4()))
	return wrapExpr("cmp", d)
}

func exprMetaOIFName() []byte {
	var d []byte
	d = putAttr(d, nftaMetaDreg, be32(nftReg2))
	d = putAttr(d, nftaMetaKey, be32(nftMetaOifname))
	return wrapExpr("meta", d)
}

func exprCmpIfName(ifname string) []byte {
	name16 := make([]byte, 16)
	copy(name16, []byte(ifname))

	var d []byte
	d = putAttr(d, nftaCmpSreg, be32(nftReg2))
	d = putAttr(d, nftaCmpOp, be32(nftCmpEq))
	d = putNestAttr(d, nftaCmpData, dataValue(name16))
	return wrapExpr("cmp", d)
}

func exprMasq() []byte {
	return wrapExpr("masq", nil)
}

func wrapExpr(name string, data []byte) []byte {
	var exprAttrs []byte
	exprAttrs = putAttr(exprAttrs, nftaExprName, zstr(name))
	exprAttrs = putAttr(exprAttrs, nftaExprData, data)
	return putNestAttr(nil, nftaListElem, exprAttrs)
}

func recvAcks(fd int, want ...uint32) error {
	expected := make(map[uint32]bool, len(want))
	for _, seq := range want {
		expected[seq] = false
	}

	buf := make([]byte, 64*1024)
	got := 0

	for got < len(expected) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("recv netlink: %w", err)
		}

		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			msgLen := int(binary.NativeEndian.Uint32(buf[off : off+4]))
			if msgLen < unix.NLMSG_HDRLEN || off+align4(msgLen) > n {
				return fmt.Errorf("invalid netlink reply")
			}

			msgType := binary.NativeEndian.Uint16(buf[off+4 : off+6])
			msgSeq := binary.NativeEndian.Uint32(buf[off+8 : off+12])

			if msgType == unix.NLMSG_ERROR {
				if msgLen < unix.NLMSG_HDRLEN+4 {
					return fmt.Errorf("shot NLMSG_ERROR")
				}
				errno := int32(binary.NativeEndian.Uint32(buf[off+16 : off+20]))
				if errno != 0 {
					return fmt.Errorf("netlink errno=%d seq=%d", -errno, msgSeq)
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
