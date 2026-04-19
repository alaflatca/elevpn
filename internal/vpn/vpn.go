package vpn

import (
	"elevpn/internal/netlink"
	"fmt"
	"log"
	"os"
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

func ExternalInterface() (string, error) {
	externalIfr, err := netlink.GetDefaultExternalInterface()
	if err != nil {
		return "", err
	}
	return externalIfr, nil
}

func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}
