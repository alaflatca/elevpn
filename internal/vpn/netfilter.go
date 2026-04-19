package vpn

import (
	"elevpn/internal/netlink"
	"fmt"
	"net"
)

type MasqueradeSpec struct {
	TableName    string // vpnnat
	ChainName    string // postrouting
	SrcCIDR      string // "10.77.0.0/24"
	OutInterface string // eth0
}

type Masquerade struct {
	spec MasqueradeSpec
}

func NewMasquerade(spec MasqueradeSpec) *Masquerade {
	return &Masquerade{spec: spec}
}

func (m *Masquerade) Apply() error {
	if m.spec.TableName == "" {
		return fmt.Errorf("table name is empty")
	}
	if m.spec.ChainName == "" {
		return fmt.Errorf("chain name is empty")
	}
	if m.spec.OutInterface == "" {
		return fmt.Errorf("table name is empty")
	}
	if len(m.spec.OutInterface) >= 16 {
		return fmt.Errorf("oif name too long: %q", m.spec.OutInterface)
	}

	_, ipnet, err := net.ParseCIDR(m.spec.SrcCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	ip4 := ipnet.IP.To4() // mask 가 적용된 IP 대역
	mask4 := net.IP(ipnet.Mask).To4()
	if ip4 == nil || mask4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	cfg := netlink.NFTMasqConfig{
		TableName:    m.spec.TableName,
		ChainName:    m.spec.ChainName,
		SrcIP:        ip4,
		SrcMask:      mask4,
		OutInterface: m.spec.OutInterface,
	}

	return netlink.ApplyMasquerade(cfg)
}

func (m *Masquerade) Cleanup() error {
	return nil
}

func (m *Masquerade) Name() string {
	return fmt.Sprintf("Masquerade (%s)", m.spec.TableName)
}
