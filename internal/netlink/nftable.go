package netlink

import (
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

func ApplyMasquerade(spec NFTMasqConfig) error {
	// NETLINK_NETFILTER 소켓 생성/바인드
	fd, err := openNetlink(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open NETLINK_NETFILTER: %w", err)
	}
	defer unix.Close(fd)

	packet := batchMsg(1, nfnlMsgBatchBegin)
	packet = append(packet, buildNewTableMsg(2, spec.TableName)...)
	packet = append(packet, buildNewChainMsg(3, spec.TableName, spec.ChainName)...)
	packet = append(packet, buildNewMasqRuleMsg(4, spec.TableName, spec.ChainName, spec.SrcIP, spec.SrcMask, spec.OutInterface)...)
	packet = append(packet, batchMsg(5, nfnlMsgBatchEnd)...)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send nft batch: %w", err)
	}

	// return recvAcks(fd, 1, 2, 3, 4, 5)
	return recvAcks(fd, 2, 3, 4)
}

func nftMsg(seq uint32, msgType uint16, flags uint16, family byte, attrs []byte) []byte {
	// msgType이 만약 8이라고 가정한다면
	// before: 0000 1010 0000 0000 --->  after: 0000 1010 0000 1000
	typ := uint16((nfnlSubsysNftables << 8) | int(msgType))
	body := append(nfgen(family, 0), attrs...)
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
	// 여기까지 작업 : ip saddr 10.77.0.0/24

	exprs = append(exprs, exprMetaOIFName()...)
	exprs = append(exprs, exprCmpIfName(oifName)...)
	// 네트워크 인터페이스 확인 작업 "eth0"
	exprs = append(exprs, exprMasq()...)

	var attrs []byte
	attrs = putAttr(attrs, nftaRuleTable, zstr(tableName))
	attrs = putAttr(attrs, nftaRuleChain, zstr(chainName))
	attrs = putAttr(attrs, nftaRuleExpressions, exprs)

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_APPEND)
	return nftMsg(seq, nftMsgNewRule, flags, nfprotoIPv4, attrs)
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
	exprAttrs = putNestAttr(exprAttrs, nftaExprData, data)
	return putNestAttr(nil, nftaListElem, exprAttrs)
}
