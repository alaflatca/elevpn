package netlink

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

func AddHostRoute(ipv4, gateway net.IP, ifIndex int) error {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	packet := buildAddHostRoute(1, ipv4, gateway, ifIndex)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	if err := recvAcks(fd, 1); err != nil {
		return err
	}

	return nil
}

func DelHostRoute(ipv4, gateway net.IP, ifIndex int) error {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	packet := buildDelHostRoute(1, ipv4, gateway, ifIndex)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	return nil
}

func RestoreDefaultRoute(gateway net.IP, ifIndex int) error {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	packet := buildRestoreDefaultRoute(1, gateway, ifIndex)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	return recvAcks(fd, 1)
}

func ReplaceDefaultRoute(ifIndex int) error {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	packet := buildReplaceDefaultRoute(1, ifIndex)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	return recvAcks(fd, 1)
}

func buildRoutePayload(dstLen uint8, scope uint8, dst, gw net.IP, ifIndex int) []byte {
	msg := newBaseRtmsg()
	msg.DstLen = dstLen
	msg.Scope = scope
	header := rtgen(msg)

	var attrs []byte
	if dst != nil && dstLen > 0 {
		attrs = putAttr(attrs, unix.RTA_DST, dst)
	}
	if gw != nil {
		attrs = putAttr(attrs, unix.RTA_GATEWAY, gw)
	}
	if ifIndex > 0 {
		oifAttr := make([]byte, 4)
		binary.NativeEndian.PutUint32(oifAttr[0:4], uint32(ifIndex))
		attrs = putAttr(attrs, unix.RTA_OIF, oifAttr)
	}

	return append(header, attrs...)
}

func buildAddHostRoute(seq uint32, dst4, gateway net.IP, ifIndex int) []byte {
	payload := buildRoutePayload(32, unix.RT_SCOPE_UNIVERSE, dst4, gateway, ifIndex)
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL

	return nlMsg(seq, unix.RTM_NEWROUTE, uint16(flags), payload)
}

func buildDelHostRoute(seq uint32, dst4, gateway net.IP, ifIndex int) []byte {
	payload := buildRoutePayload(32, unix.RT_SCOPE_UNIVERSE, dst4, gateway, ifIndex)
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK

	return nlMsg(seq, unix.RTM_DELROUTE, uint16(flags), payload)
}

func buildReplaceDefaultRoute(seq uint32, ifIndex int) []byte {
	payload := buildRoutePayload(0, unix.RT_SCOPE_LINK, nil, nil, ifIndex)
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE

	return nlMsg(seq, unix.RTM_NEWROUTE, uint16(flags), payload)
}

func buildRestoreDefaultRoute(seq uint32, gw net.IP, ifIndex int) []byte {
	payload := buildRoutePayload(0, unix.RT_SCOPE_UNIVERSE, nil, gw, ifIndex)
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE

	return nlMsg(seq, unix.RTM_NEWROUTE, uint16(flags), payload)
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
