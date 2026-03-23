package vpn

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type MasqueradeSpec struct {
	TableName string // vpnnat
	ChainName string // postrouting
	SrcCIDR   string // "10.77.0.1/24"
	OIFName   string // "tun0"
}

type RoutingSpec struct {
	ServerIP    string
	Gateway     string
	RealOIFName string
	TunOIFName  string
}

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

	ip4 := net.ParseIP(spec.ServerIP)
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	gateway := net.ParseIP(spec.Gateway)
	if gateway == nil {
		return fmt.Errorf("only gateway IPv4 is supported")
	}

	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	defer unix.Close(fd)

	// packet =
	// packet = append()
	// packet = append()
	// packet = append()

	if err := unix.Sendto(fd, []byte{}, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send nrt: %w", err)
	}

	return recvAcks(fd, 1, 2, 3)
}

func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}
