package client

import (
	"context"
	"elevpn/internal/netlink"
	"elevpn/internal/protocol"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	defaultHandshakeTimeout  = 10 * time.Second
	defaultKeepaliveInterval = 10 * time.Second
)

type ClientConfig struct {
	ListenAddr      string
	ServerEndpoint  string
	ServerRouteIP   string
	TunName         string
	ServerRouteCIDR string
	PSK             string
	AuthKey         []byte
}

type Client struct {
	cfg ClientConfig

	cipherSuite *protocol.CipherSuite
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

	if c.PSK == "" {
		return errors.New("psk must not be empty")
	}
	c.AuthKey = []byte(c.PSK)

	return nil
}

func New(cfg ClientConfig) (*Client, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	cipherSuite, err := protocol.NewCipherSuite(cfg.AuthKey)
	if err != nil {
		return nil, err
	}

	return &Client{cfg: cfg, cipherSuite: cipherSuite}, nil
}

func (c *Client) Run(ctx context.Context) error {
	conn, err := c.DialUDP(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	result, err := c.handshake(conn)
	if err != nil {
		return err
	}

	clientTunCIDR := result.tunnelIP.String() + "/32"
	tunDevice, err := tun.New(c.cfg.TunName, clientTunCIDR, result.mtu)
	if err != nil {
		return err
	}

	routeInfo, err := netlink.GetDefaultRoute()
	if err != nil {
		return err
	}
	bypassCIDRs := buildBypassCIDRs(c.cfg.ServerRouteCIDR)

	route, err := vpn.NewRoute(vpn.RouteSpec{
		ServerRouteIP:        c.cfg.ServerRouteIP,
		Gateway:              routeInfo.Gateway.String(),
		GatewayInterfaceName: routeInfo.InterfaceName,
		TunnelInterfaceName:  c.cfg.TunName,
		BypassCIDRs:          bypassCIDRs,
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

	session := &session{
		tun:    tunDevice,
		conn:   conn,
		peerID: result.peerID,

		cipher: result.cipher,

		clientSendSequence: result.clientSequence,
		serverReplayWindow: result.serverReplayWindow,
	}

	return session.run(ctx)
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
