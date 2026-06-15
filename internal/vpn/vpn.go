package vpn

import (
	"elevpn/internal/netlink"
	"fmt"
	"log"
)

type VpnComponent interface {
	Apply() error
	Cleanup() error
	Name() string
}

type VpnManager struct {
	components []VpnComponent
}

func (m *VpnManager) ApplyAll(components ...VpnComponent) error {
	for _, c := range components {
		if err := c.Apply(); err != nil {
			m.Teardown()
			return fmt.Errorf("[%s] failed to apply: %v", c.Name(), err)
		}

		m.components = append(m.components, c)
	}

	return nil
}

func (m *VpnManager) Teardown() {
	for i := len(m.components) - 1; i >= 0; i-- {
		c := m.components[i]

		if err := c.Cleanup(); err != nil {
			log.Printf("[%s] failed to cleanup: %v", c.Name(), err)
		}
	}
}

func ExternalInterface() (netlink.DefaultRoute, error) {
	externalIfr, err := netlink.GetDefaultRoute()
	if err != nil {
		return netlink.DefaultRoute{}, err
	}
	return externalIfr, nil
}
