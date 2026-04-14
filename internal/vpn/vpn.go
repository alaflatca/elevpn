package vpn

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

type VpnComponent interface {
	Apply() error
	Cleanup() error
	Name() string
}

type VpnManager struct {
	components []VpnComponent
}

func (m *VpnManager) RegisterAndApply(c VpnComponent) error {

	if err := c.Apply(); err != nil {
		return fmt.Errorf("[%s] failed to apply: %v", c.Name(), err)
	}

	m.components = append(m.components, c)
	return nil
}

func (m *VpnManager) Teardown() {
	for _, c := range m.components {
		if err := c.Cleanup(); err != nil {
			log.Printf("[%s] %v ", c.Name(), err)
		}
	}
}

//	func UnsetMasquerade() error {
//		openNetlink(unix.NETLINK_NETFILTER)
//	}

// func ExternalInterface() (string, error) {
// 	// NETLINK_NETFILTER 소켓 생성/바인드
// 	fd, err := openNetlink(unix.NETLINK_ROUTE)
// 	if err != nil {
// 		return "", fmt.Errorf("open NETLINK_ROUTE: %w", err)
// 	}
// 	defer unix.Close(fd)

// 	packet := buildAddHostRouteMsg(1, ip4, gateway, ifa.Index)
// 	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
// 		return fmt.Errorf("send rt: %w", err)
// 	}
// 	if err := recvAcks(fd, 1); err != nil {
// 		return err
// 	}

// 	packet = buildReplaceDefaultRouteMsg(2, tunIfa.Index)
// 	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
// 		return fmt.Errorf("send rt: %w", err)
// 	}
// 	if err := recvAcks(fd, 2); err != nil {
// 		return err
// 	}

// 	return nil
// }

func ExternalInterface() (string, error) {
	// NETLINK_NETFILTER 소켓 생성/바인드
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return "", fmt.Errorf("open NETLINK_NETFILTER: %w", err)
	}
	defer unix.Close(fd)

	externalIfr, err := GetDefaultExternalInterface(fd)
	if err != nil {
		return "", err
	}

	return externalIfr, nil
}

func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}
