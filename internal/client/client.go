package client

import (
	"context"
	"elevpn/internal/netlink"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
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
	log.Println("runTunnel start")

	// initval, eventfd counter 초기값
	// EFD_CLOEXEC, exec 시 fd 자동 close
	// EFD_NONBLOCK, read/write가 block되지 않게 함
	eventFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("failed to Eventfd: %v", err)
	}
	defer unix.Close(eventFd)

	errGroup, errCtx := errgroup.WithContext(ctx)

	context.AfterFunc(errCtx, func() {
		var eventBuf [8]byte
		binary.NativeEndian.PutUint64(eventBuf[:], 1)
		if _, err := unix.Write(eventFd, eventBuf[:]); err != nil {
			log.Printf("failed to write eventfd (AfterFunc): %v", err)
		}

		log.Println("after func start")
		if err := conn.Close(); err != nil {
			log.Printf("failed to udp close: %v", err)
		}

		log.Println("after func end")
	})

	errGroup.Go(func() error {
		log.Println("tunToUdp start")
		if err := tunToUdp(errCtx, tunDevice, conn, eventFd); err != nil {
			log.Printf("tunToUdp end(%v)", err)
			return fmt.Errorf("failed to TUN To UDP: %w", err)
		}
		log.Println("tunToUdp end")
		return nil
	})
	errGroup.Go(func() error {
		log.Println("udpToTun start")
		if err := udpToTun(errCtx, conn, tunDevice); err != nil {
			log.Printf("udpToTun end(%v)", err)
			return fmt.Errorf("failed to UDP to TUN: %w", err)
		}
		log.Println("udpToTun end")
		return nil
	})

	err = errGroup.Wait()
	if errors.Is(err, context.Canceled) {
		log.Println("runTunnel end (context.Canceled)")
		return nil
	}

	log.Println("runTunnel end")

	return err
}

func tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn, eventFd int) error {
	buf := make([]byte, 65535)
	for {
		n, err := tunDevice.ReadContext(ctx, buf, eventFd)
		if err != nil {
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
			written, err := tunDevice.WriteContext(ctx, buf[:n])
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
