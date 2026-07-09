package client

import (
	"context"
	"elevpn/internal/netlink"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/sync/errgroup"
)

type Client struct {
	cfg ClientConfig
}

type ClientConfig struct {
	ListenAddr      string
	ServerEndpoint  string
	ServerRouteIP   string
	TunName         string
	TunAddrCIDR     string
	ServerRouteCIDR string
}

func (c *ClientConfig) normalize() error {
	host, _, err := net.SplitHostPort(c.ServerEndpoint)
	if err != nil {
		return fmt.Errorf("failed to split host:port: %v", err)
	}
	c.ServerRouteIP = host

	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		return fmt.Errorf("server endpoint host must be IPv4: %v", host)
	}
	c.ServerRouteCIDR = ip4.String() + "/32"

	return nil
}

func New(cfg ClientConfig) (*Client, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	return &Client{cfg: cfg}, nil
}

func (c *Client) Run(ctx context.Context) error {
	routeInfo, err := netlink.GetDefaultRoute()
	if err != nil {
		return err
	}

	tunDevice, err := tun.New(c.cfg.TunName, c.cfg.TunAddrCIDR)
	if err != nil {
		return err
	}

	route, err := vpn.NewRoute(vpn.RouteSpec{
		ServerRouteIP:        c.cfg.ServerRouteIP,
		Gateway:              routeInfo.Gateway.String(),
		GatewayInterfaceName: routeInfo.InterfaceName,
		TunnelInterfaceName:  c.cfg.TunName,
	})
	if err != nil {
		return err
	}

	manager := vpn.VpnManager{}
	defer manager.Teardown()

	components := []vpn.VpnComponent{
		tunDevice,
		route,
	}

	if err := manager.ApplyAll(components...); err != nil {
		return err
	}

	conn, err := c.DialUDP(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	return c.runTunnel(ctx, tunDevice, conn)
}

func (c *Client) runTunnel(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
	errGroup, errCtx := errgroup.WithContext(ctx)

	context.AfterFunc(errCtx, func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to udp close: %v", err)
		}
		if err := tunDevice.Cleanup(); err != nil {
			log.Printf("failed to tun close: %v", err)
		}
	})

	errGroup.Go(func() error {
		if err := tunToUdp(errCtx, tunDevice, conn); err != nil {
			return fmt.Errorf("failed to TUN To UDP: %v", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := udpToTun(errCtx, conn, tunDevice); err != nil {
			return fmt.Errorf("failed to UDP to TUN: %v", err)
		}
		return nil
	})

	err := errGroup.Wait()
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}

	return err
}

func tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
	buf := make([]byte, 65535)
	for {
		n, err := tunDevice.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n > 0 {
			written, err := conn.Write(buf[:n])
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
	}
}

func udpToTun(ctx context.Context, conn *net.UDPConn, tunDevice *tun.Tun) error {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n > 0 {
			written, err := tunDevice.Write(buf[:n])
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if written != n {
				return io.ErrShortWrite
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
