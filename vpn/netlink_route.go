package vpn

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

type rtmsg struct {
	Family   byte
	DstLen   byte
	SrcLen   byte
	Tos      byte
	Table    byte
	Protocol byte
	Scope    byte
	Type     byte
	Flags    uint32
}

func rtgen(msg rtmsg) []byte {
	b := make([]byte, 12)
	b[0] = msg.Family
	b[1] = msg.DstLen
	b[2] = msg.SrcLen
	b[3] = msg.Tos
	b[4] = msg.Table
	b[5] = msg.Protocol
	b[6] = msg.Scope
	b[7] = msg.Type
	binary.NativeEndian.PutUint32(b[8:12], msg.Flags)

	return b
}

// func buildDelHostRouteMsg(seq uint32)

func buildAddHostRouteMsg(seq uint32, dst4, gw4 net.IP, oif int) []byte {
	payload := buildAddHostRoutePayload(dst4, gw4, oif)

	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL
	return nlMsg(seq, unix.RTM_NEWROUTE, uint16(flags), payload)
}

func buildAddHostRoutePayload(ip4 net.IP, gateway net.IP, ifindex int) []byte {
	msg := newBaseRtmsg()
	msg.DstLen = 32
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	header := rtgen(msg)

	var attrs []byte
	attrs = putAttr(attrs, unix.RTA_DST, ip4)
	attrs = putAttr(attrs, unix.RTA_GATEWAY, gateway)

	oifAttr := make([]byte, 4)
	binary.NativeEndian.PutUint32(oifAttr[0:4], uint32(ifindex))
	attrs = putAttr(attrs, unix.RTA_OIF, oifAttr)

	return append(header, attrs...)
}

func buildReplaceDefaultRouteMsg(seq uint32, oif int) []byte {
	payload := buildReplaceDefaultRoutePayload(oif)

	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	return nlMsg(seq, unix.RTM_NEWROUTE, uint16(flags), payload)
}

func buildReplaceDefaultRoutePayload(tunOIFIndex int) []byte {
	msg := newBaseRtmsg()
	msg.DstLen = 0
	msg.Scope = unix.RT_SCOPE_LINK
	header := rtgen(msg)

	var attrs []byte

	oifAttr := make([]byte, 4)
	binary.NativeEndian.PutUint32(oifAttr, uint32(tunOIFIndex))
	attrs = putAttr(attrs, unix.RTA_OIF, oifAttr)

	return append(header, attrs...)
}

func newBaseRtmsg() rtmsg {
	return rtmsg{
		Family:   unix.AF_INET,
		SrcLen:   0,
		Tos:      0,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Type:     unix.RTN_UNICAST,
		Flags:    0,
	}
}
