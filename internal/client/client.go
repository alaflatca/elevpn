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
	Addr       string
	ServerAddr string
	TunName    string
	CIDR       string
}

func New(cfg ClientConfig) (*Client, error) {
	return &Client{
		cfg: cfg,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	tun := tun.New(c.cfg.TunName, c.cfg.CIDR)

	route := vpn.NewRoute(vpn.RouteSpec{
		ServerIP: c.cfg.ServerAddr,
	})

	manager := vpn.VpnManager{}
	if err := manager.RegisterAndApply(tun); err != nil {
		return err
	}
	if err := manager.RegisterAndApply(route); err != nil {
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
	conn, err := net.ListenPacket("udp", c.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("binding to udp %s: %v", c.cfg.Addr, err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp", c.cfg.ServerAddr)
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
