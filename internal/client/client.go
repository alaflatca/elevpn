package client

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

	peerID, err := c.handshake(ctx, conn)
	if err != nil {
		return err
	}

	return c.runTunnel(ctx, tunDevice, conn, peerID)
}

func (c *Client) runTunnel(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn, peerID uint64) error {
	// initval, eventfd counter 초기값
	// EFD_CLOEXEC, exec 시 fd 자동 close
	// EFD_NONBLOCK, read/write가 block되지 않게 함
	eventFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("failed to Eventfd: %v", err)
	}
	defer unix.Close(eventFd)

	session := &tunnelSession{
		tun:     tunDevice,
		conn:    conn,
		eventFd: eventFd,
		peerID:  peerID,
	}

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
		if err := tunToUdp(errCtx, session); err != nil {
			return fmt.Errorf("failed to TUN To UDP: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := udpToTun(errCtx, session); err != nil {
			return fmt.Errorf("failed to UDP to TUN: %w", err)
		}
		return nil
	})

	err = errGroup.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}

func (c *Client) handshake(ctx context.Context, conn *net.UDPConn) (uint64, error) {
	m := &protocol.Message{
		Type: protocol.MessageTypeAloha,
	}
	packet, err := protocol.Encode(m)
	if err != nil {
		return 0, err
	}
	_, err = conn.Write(packet)
	if err != nil {
		return 0, err
	}

	recvBuf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize)
	n, err := conn.Read(recvBuf)
	if err != nil {
		return 0, err
	}

	message, err := protocol.Decode(recvBuf[:n])
	if err != nil {
		return 0, err
	}
	if message.Type != protocol.MessageTypeWelcome {
		return 0, fmt.Errorf("unexpected message type: expected=%d actual=%d", protocol.MessageTypeWelcome, message.Type)
	}

	return message.PeerID, nil
}

func tunToUdp(ctx context.Context, sess *tunnelSession) error {
	buf := make([]byte, protocol.MaxPayloadSize)
	for {
		n, err := sess.tun.ReadContext(ctx, buf, sess.eventFd)
		if err != nil {
			return err
		}
		if n > 0 {
			message := protocol.Message{
				Type:    protocol.MessageTypeData,
				PeerID:  sess.peerID,
				Payload: buf[:n],
			}
			packet, err := protocol.Encode(&message)
			if err != nil {
				return err
			}
			written, err := sess.conn.Write(packet)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if written != len(packet) {
				return io.ErrShortWrite
			}
		}
	}
}

func udpToTun(ctx context.Context, sess *tunnelSession) error {
	buf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize)
	for {
		n, err := sess.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n > 0 {
			packet, err := protocol.Decode(buf[:n])
			if err != nil {
				return err
			}
			if packet.Type != protocol.MessageTypeData {
				return fmt.Errorf("unexpected message type: expected=%d actual=%d", protocol.MessageTypeData, packet.Type)
			}
			written, err := sess.tun.WriteContext(ctx, packet.Payload)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if written != len(packet.Payload) {
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
