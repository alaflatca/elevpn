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

	routeInfo, err := netlink.GetDefaultRoute()
	if err != nil {
		return err
	}
	log.Printf("default route info, index: %d, name: %q, gateway: %q\n", routeInfo.InterfaceIndex, routeInfo.InterfaceName, routeInfo.Gateway.String())

	tunDevice := tun.New(c.cfg.TunName, c.cfg.TunAddrCIDR)

	components := []vpn.VpnComponent{
		tunDevice,
		vpn.NewRoute(vpn.RouteSpec{
			ServerIP:    c.cfg.ServerEndpoint,
			Gateway:     routeInfo.Gateway.String(),
			RealOIFName: routeInfo.InterfaceName,
			TunOIFName:  c.cfg.TunName,
		}),
	}

	if err := manager.ApplyAll(components...); err != nil {
		return err
	}

	conn, err := c.DialUDP(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

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

	err = errGroup.Wait()
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
