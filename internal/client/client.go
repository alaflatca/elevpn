package client

import (
	"context"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"fmt"
	"net"
)

type Client struct {
	cfg ClientConfig
}

type ClientConfig struct {
	ListenAddr      string
	ServerEndpoint  string
	TunName         string
	TunAddrCIDR     string
	ServerRouteCIDR string
}

func (c *ClientConfig) Normalize() error {
	host, _, err := net.SplitHostPort(c.ServerEndpoint)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid server endpoint host: %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("server endpoint host must be IPv4: %q", host)
	}
	c.ServerRouteCIDR = ip4.String() + "/32"

	return nil
}

func New(cfg ClientConfig) (*Client, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	return &Client{
		cfg: cfg,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	manager := vpn.VpnManager{}
	defer manager.Teardown()

	tunDevice := tun.New(c.cfg.TunName, c.cfg.TunAddrCIDR)

	components := []vpn.VpnComponent{
		tunDevice,
		vpn.NewRoute(vpn.RouteSpec{
			ServerIP: c.cfg.ServerEndpoint,
		}),
	}

	if err := manager.ApplyAll(components...); err != nil {
		return err
	}

	conn, err := c.DialUDP(ctx)
	if err != nil {
		return err
	}

	go tunToUdp(ctx, tunDevice, conn)
	go udpToTun(ctx, conn, tunDevice)

	<-ctx.Done()

	return nil
}

func tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) {

}
func udpToTun(ctx context.Context, conn *net.UDPConn, tunDevice *tun.Tun) {

}

func (c *Client) DialUDP(ctx context.Context) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr("udp", c.cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed resolve laddr: %v", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", c.cfg.ServerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed resolve raddr: %v", err)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial udp: %v", err)
	}
	return conn, nil
}
