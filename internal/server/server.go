package server

import (
	"context"
	"elevpn/internal/netlink"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"fmt"
	"log"
	"net"

	"golang.org/x/sync/errgroup"
)

type Server struct {
	cfg ServerConfig
}

type ServerConfig struct {
	ListenAddr     string
	TunName        string
	TunAddrCIDR    string
	VPNNetworkCIDR string
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{cfg: cfg}, nil
}

func (s *Server) normalize() error {
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	routeInfo, err := netlink.GetDefaultRoute()
	if err != nil {
		return err
	}

	tunDevice, err := tun.New(s.cfg.TunName, s.cfg.TunAddrCIDR)
	if err != nil {
		return err
	}

	components := []vpn.VpnComponent{
		tunDevice,
		vpn.NewIPForward(),
		vpn.NewMasquerade(vpn.MasqueradeSpec{
			TableName:    "vpnnat",
			ChainName:    "vpn-postrouting",
			SrcCIDR:      s.cfg.VPNNetworkCIDR,
			OutInterface: routeInfo.InterfaceName,
		}),
	}

	manager := vpn.VpnManager{}
	defer manager.Teardown()

	if err := manager.ApplyAll(components...); err != nil {
		return err
	}

	conn, err := s.ListenUDP(ctx)
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
		return nil
	})

	errGroup.Go(func() error {
		return nil
	})

	return nil
}

func (s *Server) ListenUDP(ctx context.Context) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("binding to udp %s: %v", s.cfg.ListenAddr, err)
	}
	return conn, nil
}
