package server

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const (
	nlaFNested = 1 << 15

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

	// bitwise / cmp op
	nftBitwiseBool = 0
	nftCmpEq       = 0

	// meta key
	nftMetaOifname = 7
)

func align4(n int) int {
	return (n + 3) &^ 3
}

func native32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
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

func zstr(s string) []byte {
	return append([]byte(s), 0)
}

func putAttr(buf []byte, typ uint16, payload []byte) []byte {
	l := 4 + len(payload)

	h := make([]byte, 4)
	binary.NativeEndian.PutUint16(h[0:2], uint16(l))
	binary.NativeEndian.PutUint16(h[2:4], typ)

	buf = append(buf, h...)
	buf = append(buf, payload...)

	if pad := align4(l) - l; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	return buf
}

func putNestAttr(buf []byte, typ uint16, nested []byte) []byte {
	return putAttr(buf, typ|nlaFNested, nested)
}

func nlMsg(seq uint32, msgType uint16, flags uint16, payload []byte) []byte {
	h := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(h[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(h[4:6], msgType)
	binary.NativeEndian.PutUint16(h[6:8], flags)
	binary.NativeEndian.PutUint32(h[8:12], seq)
	binary.NativeEndian.PutUint32(h[12:16], 0)
	return append(h, payload...)
}

func openNetlink(proto int) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, proto)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
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
					return fmt.Errorf("short NLMSG_ERROR")
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

func rtmsg(family, dstLen, table, protocol, scope, typ byte, flags uint32) []byte {
	b := make([]byte, 12)
	b[0] = family
	b[1] = dstLen
	b[2] = 0 // rtm_src_len
	b[3] = 0 // rtm_tos
	b[4] = table
	b[5] = protocol
	b[6] = scope
	b[7] = typ
	copy(b[8:12], native32(flags))
	return b
}

func buildIPv4RouteMsg(seq uint32, dstLen uint8, dst net.IP, oifIndex int, gateway net.IP) []byte {
	scope := byte(unix.RT_SCOPE_LINK)
	if gateway != nil {
		scope = byte(unix.RT_SCOPE_UNIVERSE)
	}

	rtm := rtmsg(
		unix.AF_INET,
		dstLen,
		byte(unix.RT_TABLE_MAIN),
		byte(unix.RTPROT_STATIC),
		scope,
		byte(unix.RTN_UNICAST),
		0,
	)

	var attrs []byte
	if dstLen > 0 && dst != nil {
		attrs = putAttr(attrs, unix.RTA_DST, dst.To4())
	}
	if gateway != nil {
		attrs = putAttr(attrs, unix.RTA_GATEWAY, gateway.To4())
	}
	attrs = putAttr(attrs, unix.RTA_OIF, native32(uint32(oifIndex)))

	body := append(rtm, attrs...)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	return nlMsg(seq, unix.RTM_NEWROUTE, flags, body)
}

func batchMsg(seq uint32, msgType uint16) []byte {
	body := nfgen(byte(unix.AF_UNSPEC))
	return nlMsg(seq, msgType, unix.NLM_F_REQUEST|unix.NLM_F_ACK, body)
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

func buildNewMasqRuleMsg(seq uint32, tableName, chainName string, networkIP, mask4 net.IP, oifName string) []byte {
	var exprs []byte
	exprs = append(exprs, exprPayloadIPv4Saddr()...)
	exprs = append(exprs, exprBitwiseMask(mask4)...)
	exprs = append(exprs, exprCmpIPv4(networkIP)...)
	exprs = append(exprs, exprMetaOIFName()...)
	exprs = append(exprs, exprCmpIfName(oifName)...)
	exprs = append(exprs, exprMasq()...)

	var attrs []byte
	attrs = putAttr(attrs, nftaRuleTable, zstr(tableName))
	attrs = putAttr(attrs, nftaRuleChain, zstr(chainName))
	attrs = putNestAttr(attrs, nftaRuleExpressions, exprs)

	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_APPEND)
	return nftMsg(seq, nftMsgNewRule, flags, nfprotoIPv4, attrs)
}

func nftMsg(seq uint32, msgType uint16, flags uint16, family byte, attrs []byte) []byte {
	typ := uint16((nfnlSubsysNftables << 8) | int(msgType))
	body := append(nfgen(family), attrs...)
	return nlMsg(seq, typ, flags, body)
}

func nfgen(family byte) []byte {
	return []byte{family, nfnlVersion, 0, 0}
}

func wrapExpr(name string, data []byte) []byte {
	var exprAttrs []byte
	exprAttrs = putAttr(exprAttrs, nftaExprName, zstr(name))
	exprAttrs = putNestAttr(exprAttrs, nftaExprData, data)
	return putNestAttr(nil, nftaListElem, exprAttrs)
}

func dataValue(v []byte) []byte {
	var b []byte
	b = putAttr(b, nftaDataValue, v)
	return b
}

func exprPayloadIPv4Saddr() []byte {
	var d []byte
	d = putAttr(d, nftaPayloadDreg, be32(nftReg1))
	d = putAttr(d, nftaPayloadBase, be32(nftPayloadNetworkHeader))
	d = putAttr(d, nftaPayloadOffset, be32(12))
	d = putAttr(d, nftaPayloadLen, be32(4))
	return wrapExpr("payload", d)
}

func exprBitwiseMask(mask4 net.IP) []byte {
	var d []byte
	d = putAttr(d, nftaBitwiseSreg, be32(nftReg1))
	d = putAttr(d, nftaBitwiseDreg, be32(nftReg1))
	d = putAttr(d, nftaBitwiseLen, be32(4))
	d = putNestAttr(d, nftaBitwiseMask, dataValue(mask4.To4()))
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
