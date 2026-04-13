package vpn

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type VpnComponent interface {
	Apply() error
	Cleanup() error
	Name() string
}

//	func UnsetMasquerade() error {
//		openNetlink(unix.NETLINK_NETFILTER)
//	}

func ExternalInterface() (string, error) {
	// NETLINK_NETFILTER 소켓 생성/바인드
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return "", fmt.Errorf("open NETLINK_ROUTE: %w", err)
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
