package vpn

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type MasqueradeSpec struct {
	TableName string // vpnnat
	ChainName string // postrouting
	SrcCIDR   string // "10.77.0.1/24"
	OIFName   string // "tun0"
}

type RoutingSpec struct {
	ServerIP    net.IP
	Gateway     net.IP
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
		return fmt.Errorf("table name is empty")
	}
	if len(spec.OIFName) >= 16 {
		return fmt.Errorf("oif name too long: %q", spec.OIFName)
	}

	_, ipnet, err := net.ParseCIDR(spec.SrcCIDR)
	if err != nil {
		return fmt.Errorf("parse cidr: %w", err)
	}

	ip4 := ipnet.IP.To4() // mask 가 적용된 IP 대역
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR is supported")
	}

	mask4 := net.IP(ipnet.Mask).To4()
	if mask4 == nil {
		return fmt.Errorf("only IPv4 mask is supported")
	}

	// NETLINK_NETFILTER 소켓 생성/바인드
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
