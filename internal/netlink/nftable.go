package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type NFTMasqConfig struct {
	TableName    string
	ChainName    string
	SrcIP        net.IP
	SrcMask      net.IP
	OutInterface string
}

func DeleteMasqueradeTable(tableName string) error {
	if tableName == "" {
		return errors.New("table name is empty")
	}
	fd, err := openNetlink(unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	packet := batchMsg(1, unix.NFNL_MSG_BATCH_BEGIN)
	packet = append(packet, buildDelTableMsg(2, tableName)...)
	packet = append(packet, batchMsg(3, unix.NFNL_MSG_BATCH_END)...)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	return recvAcks(fd, 2)
}

func ApplyMasquerade(spec NFTMasqConfig) error {
	// NETLINK_NETFILTER 소켓 생성/바인드
	fd, err := openNetlink(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open NETLINK_NETFILTER: %w", err)
	}
	defer unix.Close(fd)

	packet := batchMsg(1, unix.NFNL_MSG_BATCH_BEGIN)
	packet = append(packet, buildNewTableMsg(2, spec.TableName)...)
	packet = append(packet, buildNewChainMsg(3, spec.TableName, spec.ChainName)...)
	packet = append(packet, buildNewMasqRuleMsg(4, spec.TableName, spec.ChainName, spec.SrcIP, spec.SrcMask, spec.OutInterface)...)
	packet = append(packet, batchMsg(5, unix.NFNL_MSG_BATCH_END)...)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send nft batch: %w", err)
	}

	// return recvAcks(fd, 1, 2, 3, 4, 5)
	return recvAcks(fd, 2, 3, 4)
}

func nftMsg(seq uint32, msgType uint16, flags uint16, family byte, attrs []byte) []byte {
	// msgType이 만약 8이라고 가정한다면
	// before: 0000 1010 0000 0000 --->  after: 0000 1010 0000 1000
	typ := uint16((unix.NFNL_SUBSYS_NFTABLES << 8) | int(msgType))
	body := append(nfgen(family, 0), attrs...)
	return nlMsg(seq, typ, flags, body)
}

func buildDelTableMsg(seq uint32, tableName string) []byte {
	var attrs []byte
	attrs = putAttr(attrs, unix.NFTA_TABLE_NAME, zstr(tableName))
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	return nftMsg(seq, unix.NFT_MSG_DELTABLE, flags, unix.NFPROTO_IPV4, attrs)
}

func buildNewTableMsg(seq uint32, tableName string) []byte {
	var attrs []byte
	attrs = putAttr(attrs, unix.NFTA_TABLE_NAME, zstr(tableName))
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	return nftMsg(seq, unix.NFT_MSG_NEWTABLE, flags, unix.NFPROTO_IPV4, attrs)
}

func buildNewChainMsg(seq uint32, tableName, chainName string) []byte {
	var hookAttrs []byte
	hookAttrs = putAttr(hookAttrs, unix.NFTA_HOOK_HOOKNUM, be32(unix.NF_INET_POST_ROUTING))
	hookAttrs = putAttr(hookAttrs, unix.NFTA_HOOK_PRIORITY, beS32(nfIPPriNATSrc))

	var attrs []byte
	attrs = putAttr(attrs, unix.NFTA_CHAIN_TABLE, zstr(tableName))
	attrs = putAttr(attrs, unix.NFTA_CHAIN_NAME, zstr(chainName))
	attrs = putNestAttr(attrs, unix.NFTA_CHAIN_HOOK, hookAttrs)
	attrs = putAttr(attrs, unix.NFTA_CHAIN_TYPE, zstr("nat"))

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	return nftMsg(seq, unix.NFT_MSG_NEWCHAIN, flags, unix.NFPROTO_IPV4, attrs)
}

func buildNewMasqRuleMsg(seq uint32, tableName, chainName string, ip4, mask4 net.IP, oifName string) []byte {
	var exprs []byte
	exprs = append(exprs, exprPayloadIPv4Saddr()...) // 지나가는 패킷의 출발지 IP 주소를 읽어라
	exprs = append(exprs, exprBitwiseMask(mask4)...) // 위 주소에 서브넷 마스크를 씌워서 네트워크 대역만 남겨라
	exprs = append(exprs, exprCmpIPv4(ip4)...)       // 위 대역이 우리가 허용한 VPN대역이 맞는지 확인해라
	// 여기까지 작업 : ip saddr 10.77.0.0/24

	exprs = append(exprs, exprMetaOIFName()...)
	exprs = append(exprs, exprCmpIfName(oifName)...)
	// 네트워크 인터페이스 확인 작업 "eth0"
	exprs = append(exprs, exprMasq()...)

	var attrs []byte
	attrs = putAttr(attrs, unix.NFTA_RULE_TABLE, zstr(tableName))
	attrs = putAttr(attrs, unix.NFTA_RULE_CHAIN, zstr(chainName))
	attrs = putAttr(attrs, unix.NFTA_RULE_EXPRESSIONS, exprs)

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_APPEND)
	return nftMsg(seq, unix.NFT_MSG_NEWRULE, flags, unix.NFPROTO_IPV4, attrs)
}

func exprPayloadIPv4Saddr() []byte {
	var d []byte
	d = putAttr(d, unix.NFTA_PAYLOAD_DREG, be32(unix.NFT_REG_1))
	d = putAttr(d, unix.NFTA_PAYLOAD_BASE, be32(unix.NFT_PAYLOAD_NETWORK_HEADER))
	d = putAttr(d, unix.NFTA_PAYLOAD_OFFSET, be32(12))
	d = putAttr(d, unix.NFTA_PAYLOAD_LEN, be32(4))
	return wrapExpr("payload", d)
}

func exprBitwiseMask(mask net.IP) []byte {
	var d []byte
	d = putAttr(d, unix.NFTA_BITWISE_SREG, be32(unix.NFT_REG_1))
	d = putAttr(d, unix.NFTA_BITWISE_DREG, be32(unix.NFT_REG_1))
	d = putAttr(d, unix.NFTA_BITWISE_LEN, be32(4))
	d = putNestAttr(d, unix.NFTA_BITWISE_MASK, dataValue(mask.To4()))
	d = putNestAttr(d, unix.NFTA_BITWISE_XOR, dataValue([]byte{0, 0, 0, 0}))
	d = putAttr(d, nftaBitwiseOp, be32(unix.NFT_BITWISE_BOOL))
	return wrapExpr("bitwise", d)
}

func exprCmpIPv4(ip4 net.IP) []byte {
	var d []byte
	d = putAttr(d, unix.NFTA_CMP_SREG, be32(unix.NFT_REG_1))
	d = putAttr(d, unix.NFTA_CMP_OP, be32(unix.NFT_CMP_EQ))
	d = putNestAttr(d, unix.NFTA_CMP_DATA, dataValue(ip4.To4()))
	return wrapExpr("cmp", d)
}

func exprMetaOIFName() []byte {
	var d []byte
	d = putAttr(d, unix.NFTA_META_DREG, be32(unix.NFT_REG_2))
	d = putAttr(d, unix.NFTA_META_KEY, be32(unix.NFT_META_OIFNAME))
	return wrapExpr("meta", d)
}

func exprCmpIfName(ifname string) []byte {
	name16 := make([]byte, 16)
	copy(name16, []byte(ifname))

	var d []byte
	d = putAttr(d, unix.NFTA_CMP_SREG, be32(unix.NFT_REG_2))
	d = putAttr(d, unix.NFTA_CMP_OP, be32(unix.NFT_CMP_EQ))
	d = putNestAttr(d, unix.NFTA_CMP_DATA, dataValue(name16))
	return wrapExpr("cmp", d)
}

func exprMasq() []byte {
	return wrapExpr("masq", nil)
}

func wrapExpr(name string, data []byte) []byte {
	var exprAttrs []byte
	exprAttrs = putAttr(exprAttrs, unix.NFTA_EXPR_NAME, zstr(name))
	exprAttrs = putNestAttr(exprAttrs, unix.NFTA_EXPR_DATA, data)
	return putNestAttr(nil, unix.NFTA_LIST_ELEM, exprAttrs)
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
	b[1] = 0 // nfgenmsg version
	binary.BigEndian.PutUint16(b[2:4], resID)
	return b
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
	body := nfgen(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES)
	return nlMsg(seq, msgType, unix.NLM_F_REQUEST, body)
}
