package server

import (
	"context"
	"elevpn/internal/tun"
	"fmt"
	"log"
	"net"
	"time"
)

type Server struct {
	cfg ServerConfig
}

type ServerConfig struct {
	Addr    string
	TunName string
	CIDR    string
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{
		cfg: cfg,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	device, err := tun.Create("tun0")
	if err != nil {
		return err
	}
	fmt.Printf("tun device name: %s\n", device.Name)
	defer device.Close()

	addr, err := s.echoServerUDP(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("[server] network: %s, addr: %s\n", addr.Network(), addr.String())

	<-ctx.Done()

	return nil
}

func (s *Server) echoServerUDP(ctx context.Context) (net.Addr, error) {
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
