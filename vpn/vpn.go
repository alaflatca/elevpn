package vpn

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func SetMasquerade(spec MasqueradeSpec) error {
	if spec.TableName == "" {
		return fmt.Errorf("table name is empty")
	}
	if spec.ChainName == "" {
		return fmt.Errorf("chain name is empty")
	}
	if spec.OutInterface == "" {
		return fmt.Errorf("table name is empty")
	}
	if len(spec.OutInterface) >= 16 {
		return fmt.Errorf("oif name too long: %q", spec.OutInterface)
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
	packet = append(packet, buildNewMasqRuleMsg(4, spec.TableName, spec.ChainName, ip4, mask4, spec.OutInterface)...)
	packet = append(packet, batchMsg(5, nfnlMsgBatchEnd)...)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send nft batch: %w", err)
	}

	// return recvAcks(fd, 1, 2, 3, 4, 5)
	return recvAcks(fd, 2, 3, 4)
}

func SetRouting(spec RoutingSpec) error {
	if spec.ServerIP == "" {
		return errors.New("server ip is empty")
	}
	if spec.Gateway == "" {
		return errors.New("gateway is empty")
	}
	if spec.RealOIFName == "" {
		return errors.New("real oif name is empty")
	}
	if spec.TunOIFName == "" {
		return errors.New("tun oif name is empty")
	}

	ip4 := net.ParseIP(spec.ServerIP).To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", spec.ServerIP)
	}

	gateway := net.ParseIP(spec.Gateway).To4()
	if gateway == nil {
		return fmt.Errorf("invalid gateway address: %s", spec.Gateway)
	}

	ifa, err := net.InterfaceByName(spec.RealOIFName)
	if err != nil {
		return err
	}
	if ifa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.RealOIFName)
	}

	tunIfa, err := net.InterfaceByName(spec.TunOIFName)
	if err != nil {
		return err
	}
	if tunIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.TunOIFName)
	}

	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	defer unix.Close(fd)

	packet := buildAddHostRouteMsg(1, ip4, gateway, ifa.Index)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send rt: %w", err)
	}
	if err := recvAcks(fd, 1); err != nil {
		return err
	}

	packet = buildReplaceDefaultRouteMsg(2, tunIfa.Index)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send rt: %w", err)
	}
	if err := recvAcks(fd, 2); err != nil {
		return err
	}

	return nil
}

func ExternalInterface() error {
	// NETLINK_NETFILTER 소켓 생성/바인드
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_NETFILTER: %w", err)
	}
	defer unix.Close(fd)

	if _, err := GetDefaultExternalInterface(fd); err != nil {
		return err
	}

	return nil
}

func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}
