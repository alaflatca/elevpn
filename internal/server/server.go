package server

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
	"sync"

	"golang.org/x/sync/errgroup"
)

type ServerConfig struct {
	ListenAddr     string
	TunName        string
	TunAddrCIDR    string
	VPNNetworkCIDR string
}

func (s *ServerConfig) normalize() error {
	return nil
}

type Server struct {
	cfg      ServerConfig
	peerAddr *net.UDPAddr
	mutex    sync.RWMutex
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{cfg: cfg, mutex: sync.RWMutex{}}, nil
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

	return s.runTunnel(ctx, tunDevice, conn)
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

func (s *Server) runTunnel(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
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
		return s.tunToUdp(errCtx, tunDevice, conn)
	})
	errGroup.Go(func() error {
		return s.udpToTun(errCtx, conn, tunDevice)
	})

	err := errGroup.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}

func (s *Server) tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
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
			s.mutex.RLock()
			peerAddr := s.peerAddr
			s.mutex.RUnlock()
			if peerAddr == nil {
				continue
			}

			written, err := conn.WriteToUDP(buf[:n], peerAddr)
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

func (s *Server) udpToTun(ctx context.Context, conn *net.UDPConn, tunDevice *tun.Tun) error {
	buf := make([]byte, 65535)
	for {
		n, peerAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		s.mutex.Lock()
		s.peerAddr = peerAddr
		s.mutex.Unlock()

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
