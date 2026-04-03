package server

import (
	"context"
	"elevpn/internal/tun"
	"elevpn/vpn"
	"fmt"
	"log"
	"net"
	"time"
)

type Server struct {
	cfg ServerConfig
}

type ServerConfig struct {
	Addr         string
	CIDR         string
	OutInterface string
	TunInterface string
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{
		cfg: cfg,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	// 한 묶음
	device, err := tun.Create(s.cfg.TunInterface)
	if err != nil {
		return err
	}
	defer device.Close()

	if err := device.SetUp(); err != nil {
		return err
	}

	if err := device.SetIPv4CIDR(s.cfg.CIDR); err != nil {
		return err
	}

	if err := vpn.ExternalInterface(); err != nil {
		return err
	}

	return nil

	// net.inter
	if err := vpn.SetMasquerade(vpn.MasqueradeSpec{
		TableName:    "vpnnat",
		ChainName:    "postrouting",
		SrcCIDR:      s.cfg.CIDR,
		OutInterface: "", // tun이 아님 eth0
	}); err != nil {
		return err
	}

	if err := vpn.EnableIPForward(); err != nil {
		return err
	}

	addr, err := s.ListenUDP(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("[server] network: %s, addr: %s\n", addr.Network(), addr.String())

	<-ctx.Done()

	return nil
}

func (s *Server) ListenUDP(ctx context.Context) (net.Addr, error) {
	conn, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("binding to udp %s: %v", s.cfg.Addr, err)
	}
	go func() {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()

		for {
			recvBuf := make([]byte, 1024)
			n, clientAddr, err := conn.ReadFrom(recvBuf)
			if err != nil {
				log.Println(err)
				return
			}
			fmt.Printf("[server] client(%s) recv buf: %s\n", clientAddr, string(recvBuf[:n]))

			sendBuf := make([]byte, 0, 1024)
			sendBuf = fmt.Appendf(sendBuf, "[%s]hello client, i'm server halo?\n", time.Now().String())
			m, err := conn.WriteTo(sendBuf, clientAddr)
			if err != nil {
				return
			}

			fmt.Printf("[server] client(%s) send buf: %s\n", clientAddr, string(sendBuf[:m]))
		}
	}()

	return conn.LocalAddr(), nil
}
