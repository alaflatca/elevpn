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
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type ServerConfig struct {
	ListenAddr     string
	TunName        string
	TunAddrCIDR    string
	VPNNetworkCIDR string
	PSK            string
	AuthKey        []byte
}

func (s *ServerConfig) normalize() error {
	_, ipnet, err := net.ParseCIDR(s.VPNNetworkCIDR)
	if err != nil {
		return err
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("vpn network cidr must be IPv4: cidr=%q bits=%d", s.VPNNetworkCIDR, bits)
	}
	if ones > 30 {
		return fmt.Errorf("vpn network cidr is too small: cidr=%q prefix=%d; need /30 or larger network", s.VPNNetworkCIDR, ones)
	}

	ip4 := ipnet.IP.To4()
	networkAddr := binary.BigEndian.Uint32(ip4)
	serverAddr := networkAddr + 1

	var serverIPBytes [4]byte
	binary.BigEndian.PutUint32(serverIPBytes[:], serverAddr)
	tunAddr := netip.AddrFrom4(serverIPBytes)
	s.TunAddrCIDR = fmt.Sprintf("%s/%d", tunAddr.String(), ones)

	if s.PSK == "" {
		return fmt.Errorf("psk must not be empty")
	}
	s.AuthKey = []byte(s.PSK)

	return nil
}

type Server struct {
	mu sync.RWMutex

	cfg    ServerConfig
	peers  *peerStore
	cipher *protocol.Cipher
}

func New(cfg ServerConfig) (*Server, error) {
	if err := cfg.normalize(); err != nil {
		return nil, fmt.Errorf("failed to normalize server config: %v", err)
	}

	cipher, err := protocol.NewCipher(cfg.AuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return &Server{
		cfg:    cfg,
		peers:  newPeerStore(),
		cipher: cipher,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	routeInfo, err := netlink.GetDefaultRoute()
	if err != nil {
		return err
	}

	tunDevice, err := tun.New(s.cfg.TunName, s.cfg.TunAddrCIDR, protocol.DefaultTunnelMTU)
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
		if err := s.udpToTun(errCtx, conn, tunDevice); err != nil {
			return fmt.Errorf("failed to UDP to TUN: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := s.tunToUdp(errCtx, tunDevice, conn, eventFd); err != nil {
			return fmt.Errorf("failed to TUN To UDP: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := s.expirePeersLoop(errCtx); err != nil {
			return err
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

func (s *Server) udpToTun(ctx context.Context, conn *net.UDPConn, tunDevice *tun.Tun) error {
	buf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize+protocol.AEADTagLen)

	for {
		n, peerAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		message, err := s.cipher.DecodePacket(buf[:n], protocol.DirectionClientToServer)
		if err != nil {
			log.Printf("[udpToTun] failed to decode: %v", err)
			continue
		}

		switch message.Type {
		case protocol.MessageTypeAloha:
			err = s.handleAloha(conn, peerAddr, message)
		case protocol.MessageTypeKeepalive:
			err = s.handleKeepalive(message)
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
			if errors.Is(err, ErrReplayPacket) {
				log.Printf("[udpToTun] replay packet: %v", err)
				continue
			}
			return err
		}
	}
}

func (s *Server) tunToUdp(ctx context.Context, tunDevice *tun.Tun, conn *net.UDPConn, eventFd int) error {
	buf := make([]byte, protocol.MaxPayloadSize)
	for {
		n, err := tunDevice.ReadContext(ctx, buf, eventFd)
		if err != nil {
			return err
		}

		if n > 0 {
			destIPv4, err := extractIPv4Dst(buf[:n])
			if err != nil {
				if errors.Is(err, ErrDropPacket) {
					continue
				}
				return fmt.Errorf("failed to extract ipv4 dst: %v", err)
			}

			peer, ok := s.peers.getByTunnelIP(destIPv4)
			if !ok {
				return fmt.Errorf("not found peer ip=%v: %w", destIPv4, ErrDropPacket)
			}

			nextSeq := peer.nextSendSequence()
			message := &protocol.Message{
				Type:     protocol.MessageTypeData,
				PeerID:   peer.id,
				Sequence: nextSeq,
				Payload:  buf[:n], // 이것도 따로 복사하는게 나은지
			}
			data, err := s.cipher.EncodePacket(message, protocol.DirectionServerToClient)
			if err != nil {
				return err
			}

			written, err := conn.WriteToUDP(data, peer.addr)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if written != len(data) {
				return io.ErrShortWrite
			}
		}

	}
}

const (
	defaultPeerTimeout         = 30 * time.Second
	defaultPeerCleanupInterval = 10 * time.Second
)

func (s *Server) expirePeersLoop(ctx context.Context) error {
	ticker := time.NewTicker(defaultPeerCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			deleteCount := s.peers.deleteExpired(now, defaultPeerTimeout)
			if deleteCount > 0 {
				log.Printf("[peer] delete expired count=%d", deleteCount)
			}
		case <-ctx.Done():
			return ctx.Err()
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
		return nil, fmt.Errorf("binding to udp(%q): %v", s.cfg.ListenAddr, err)
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
	if len(packet) < 20 {
		return netip.Addr{}, fmt.Errorf("invalid ipv4 header length < 20")
	}

	// 상위 4비트: IP version
	// 하위 4비트: IHL
	version := packet[0] >> 4
	if version != 4 {
		return netip.Addr{}, fmt.Errorf("unsupported ip version=%d: %w", version, ErrDropPacket)
	}

	ihl := packet[0] & 0x0F
	if ihl < 5 {
		return netip.Addr{}, fmt.Errorf("invalid ihl: %v", ihl)
	}
	headerLen := int(ihl) * 4
	if len(packet) < headerLen {
		return netip.Addr{}, fmt.Errorf("invalid ipv4 header length: packet len=%d header len=%d", len(packet), int(ihl)*4)
	}

	totalLen := binary.BigEndian.Uint16(packet[2:4])
	if totalLen < uint16(headerLen) {
		return netip.Addr{}, fmt.Errorf("invalid ipv4 total length: total len=%d header len=%d", totalLen, headerLen)
	}
	if len(packet) < int(totalLen) {
		return netip.Addr{}, fmt.Errorf("truncated ipv4 packet: packet len=%d total len=%d", len(packet), totalLen)
	}

	/*
		header len = IPv4 헤더 길이
		total len  = IPv4 패킷 전체 길이
		packet len = 실제로 함수에 들어온 버퍼 길이
	*/

	var dst [4]byte
	copy(dst[:], packet[16:20])
	addr := netip.AddrFrom4(dst)

	return addr, nil
}
