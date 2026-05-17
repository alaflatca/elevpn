package client

import (
	"context"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"fmt"
	"net"
	"time"
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

	components := []vpn.VpnComponent{
		tun.New(c.cfg.TunName, c.cfg.TunAddrCIDR),
		vpn.NewRoute(vpn.RouteSpec{
			ServerIP: c.cfg.ServerEndpoint,
		}),
	}

	if err := manager.ApplyAll(components...); err != nil {
		return err
	}

	addr, err := c.ListenUDP(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("[client] network: %s, addr: %s\n", addr.Network(), addr.String())

	<-ctx.Done()

	return nil
}

func (c *Client) ListenUDP(ctx context.Context) (net.Addr, error) {
	conn, err := net.ListenPacket("udp", c.cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("binding to udp %s: %v", c.cfg.ListenAddr, err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp", c.cfg.ServerEndpoint)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[client] server addr: %s\n", serverAddr.String())

	go func() {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()

		for range 10 {
			sendBuf := make([]byte, 0, 1024)
			sendBuf = fmt.Appendf(sendBuf, "[%s] hello server!, i'm client ", time.Now().String())
			_, err = conn.WriteTo(sendBuf, serverAddr)
			if err != nil {
				return
			}

			recvBuf := make([]byte, 1024)
			n, svrAddr, err := conn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			fmt.Printf("[client] recv(%s) buf: %s\n", svrAddr.String(), string(recvBuf[:n]))

			time.Sleep(3 * time.Second)
		}
	}()

	return conn.LocalAddr(), nil
}
