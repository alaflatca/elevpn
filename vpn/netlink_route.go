package vpn

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

type RoutingSpec struct {
	ServerIP    string
	Gateway     string
	RealOIFName string
	TunOIFName  string
}

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

// NetRoute Header
func rtMsg(attrs []byte) []byte {

	return nlMsg()
}

func buildAddHostRouteMsg(spec RoutingSpec) error {
	msg := newBaseRtmsg()
	msg.DstLen = 32
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	header := rtgen(msg)

	return nil
}

func buildReplaceDefaultRouteMsg(tunOIFName string) error {
	msg := newBaseRtmsg()
	msg.DstLen = 0
	msg.Scope = unix.RT_SCOPE_LINK
	header := rtgen(msg)

	return nil
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
