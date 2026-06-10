package client

import (
	"context"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"fmt"
	"net"

	"golang.org/x/sync/errgroup"
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

	errGroup, errCtx := errgroup.WithContext(ctx)
	errGroup.Go(func() error {
		return tunToUdp(errCtx, tunDevice, conn)
	})
	errGroup.Go(func() error {
		return udpToTun(errCtx, conn, tunDevice)
	})
	if err := errGroup.Wait(); err != nil {
		return err
	}

	return nil
}

func tunToUdp(c context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
	ctx, cancel := context.WithCancel(c)
	defer cancel()

	buf := make([]byte, 65535)
	for {
		n, err := tunDevice.Read(buf)
		if err != nil {
			if c.Err() != nil {
				return c.Err()
			}

		}
		if n != 0 && len(buf) > 0 {
			_, err := conn.Write(buf[:n])
			if err != nil {

			}
		}

		select {
		case <-ctx.Done():
			return nil
		default:
			continue
		}
	}
}
func udpToTun(ctx context.Context, conn *net.UDPConn, tunDevice *tun.Tun) error {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {

		}

		if n != 0 && len(buf) > 0 {
			n, err := conn.Write(buf[:n])
			if err != nil {

			}
			if n == 0 {

			}
		}
	}
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
