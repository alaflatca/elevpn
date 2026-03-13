package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type MasqueradeSpec struct {
	TableName string
	ChainName string
	SrcCIDR   string
	OIFName   string
}

type RoutingSpec struct {
	ServerIP    net.IP
	Gateway     net.IP // nil이면 on-link route처럼 dev만 사용
	RealOIFName string
	TunOIFName  string
}

func SetMasquerade(spec MasqueradeSpec) error {
	if spec.TableName == "" {
		return fmt.Errorf("table name is empty")
	}
	if spec.ChainName == "" {
		return fmt.Errorf("chain name is empty")
	}
	if spec.OIFName == "" {
		return fmt.Errorf("oif name is empty")
	}
	if len(spec.OIFName) >= 16 {
		return fmt.Errorf("oif name too long: %q", spec.OIFName)
	}

	_, ipnet, err := net.ParseCIDR(spec.SrcCIDR)
	if err != nil {
		return fmt.Errorf("parse cidr: %w", err)
	}

	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR is supported")
	}

	mask4 := net.IP(ipnet.Mask).To4()
	if mask4 == nil {
		return fmt.Errorf("only IPv4 mask is supported")
	}

	fd, err := openNetlink(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open NETLINK_NETFILTER: %w", err)
	}
	defer unix.Close(fd)

	packet := batchMsg(1, nfnlMsgBatchBegin)
	packet = append(packet, buildNewTableMsg(2, spec.TableName)...)
	packet = append(packet, buildNewChainMsg(3, spec.TableName, spec.ChainName)...)
	packet = append(packet, buildNewMasqRuleMsg(4, spec.TableName, spec.ChainName, ip4, mask4, spec.OIFName)...)
	packet = append(packet, batchMsg(5, nfnlMsgBatchEnd)...)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send nft batch: %w", err)
	}

	return recvAcks(fd, 1, 2, 3, 4, 5)
}

func SetRouting(spec RoutingSpec) error {
	server4 := spec.ServerIP.To4()
	if server4 == nil {
		return fmt.Errorf("server IP must be IPv4")
	}
	if spec.RealOIFName == "" {
		return fmt.Errorf("real output interface name is empty")
	}
	if spec.TunOIFName == "" {
		return fmt.Errorf("tun interface name is empty")
	}

	realIf, err := net.InterfaceByName(spec.RealOIFName)
	if err != nil {
		return fmt.Errorf("lookup real interface %q: %w", spec.RealOIFName, err)
	}
	tunIf, err := net.InterfaceByName(spec.TunOIFName)
	if err != nil {
		return fmt.Errorf("lookup tun interface %q: %w", spec.TunOIFName, err)
	}

	var gw4 net.IP
	if spec.Gateway != nil {
		gw4 = spec.Gateway.To4()
		if gw4 == nil {
			return fmt.Errorf("gateway must be IPv4")
		}
	}

	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	defer unix.Close(fd)

	hostRoute := buildIPv4RouteMsg(1, 32, server4, realIf.Index, gw4)
	if err := unix.Sendto(fd, hostRoute, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send server host route: %w", err)
	}
	if err := recvAcks(fd, 1); err != nil {
		return fmt.Errorf("server host route ack: %w", err)
	}

	defaultRoute := buildIPv4RouteMsg(2, 0, nil, tunIf.Index, nil)
	if err := unix.Sendto(fd, defaultRoute, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send default tun route: %w", err)
	}
	if err := recvAcks(fd, 2); err != nil {
		return fmt.Errorf("default tun route ack: %w", err)
	}

	return nil
}
