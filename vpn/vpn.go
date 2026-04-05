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

	ifr, err := GetDefaultExternalInterface(fd)
	if err != nil {
		return "", err
	}

	return ifr, nil
}

func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}
