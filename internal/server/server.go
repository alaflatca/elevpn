package server

import (
	"context"
	"elevpn/internal/netlink"
	"elevpn/internal/protocol"
	"elevpn/internal/tun"
	"elevpn/internal/vpn"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
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
	cfg   ServerConfig
	mutex sync.RWMutex
	peers *peerStore
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{cfg: cfg, peers: newPeerStore()}, nil
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

func (s *Server) runTunnel(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn) error {
	eventFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return err
	}
	defer unix.Close(eventFd)

	errGroup, errCtx := errgroup.WithContext(ctx)

	context.AfterFunc(errCtx, func() {
		var eventBuf [8]byte
		binary.NativeEndian.PutUint64(eventBuf[:], 1)
		if _, err := unix.Write(eventFd, eventBuf[:]); err != nil {
			log.Printf("failed to write eventfd (AfterFunc): %v", err)
		}

		if err := conn.Close(); err != nil {
			log.Printf("failed to udp close: %v", err)
		}
	})

	errGroup.Go(func() error {
		if err := s.tunToUdp(errCtx, tunDevice, conn, eventFd); err != nil {
			return fmt.Errorf("failed to TUN To UDP: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := s.udpToTun(errCtx, conn, tunDevice); err != nil {
			return fmt.Errorf("failed to UDP to TUN: %w", err)
		}
		return nil
	})

	err = errGroup.Wait()
	if errors.Is(err, context.Canceled) {
		log.Println("runTunnel end (context.Canceled)")
		return nil
	}

	return err
}

func (s *Server) tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn, eventFd int) error {
	buf := make([]byte, protocol.MaxPayloadSize)
	for {
		n, err := tunDevice.ReadContext(ctx, buf, eventFd)
		if err != nil {
			return err
		}

		if n > 0 {
			message, err := protocol.Decode(buf[:n])
			if err != nil {
				log.Printf("[tunToUdp] failed to decode: %v", err)
				continue
			}

			peer, ok := s.peers.getByID(message.PeerID)
			if !ok {
				return fmt.Errorf("not found peer id=%d", message.PeerID)
			}

			written, err := conn.WriteToUDP(buf[:n], peer.addr)
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
	buf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize)

	for {
		n, peerAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		message, err := protocol.Decode(buf[:n])
		if err != nil {
			log.Printf("[udpToTun] failed to decode: %v", err)
			continue
		}

		switch message.Type {
		case protocol.MessageTypeAloha:
			err = s.handleAloha(conn, peerAddr)
		case protocol.MessageTypeKeepalive:
			err = s.handleKeepalive()
		case protocol.MessageTypeData:
			err = s.handleData(ctx, tunDevice, peerAddr, *message)
		default: // pass 하는게 나을지 로그를 찍을지? 쓸모없는 데이터를 굳이 로그를 찍어야하는지?
			continue
		}

		if err != nil {
			if errors.Is(err, ErrDropPacket) {
				log.Printf("[udpToTun] drop packet: %v", err)
				continue
			}
			return err
		}
	}
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

/*
tun read packet (L3 IP packet)
[IPv4 header] [transport header] [transport payload]

[IPv4 header] 20 bytes (* 9 offset Protocol 에따라 transport header 가 달라짐(tcp, udp, icmp)
byte offset
0               Version + IHL
1               DSCP/ECN
2~3             Total Length
4~5             Identification
6~7             Flags + Fragment Offset
8               TTL
9               Protocol
10~11           Header Checksum
12~15           Source IP
16~19           Destination IP
20~             Options, if IHL > 5
*/
func extractIPv4Dst(packet []byte) (netip.Addr, error) {
	if len(packet) != 20 {

	}
	destIPv4 := packet[16:19]

}
