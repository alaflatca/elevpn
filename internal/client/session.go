package client

import (
	"context"
	"elevpn/internal/protocol"
	"elevpn/internal/tun"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type session struct {
	mu      sync.Mutex
	tun     *tun.Tun
	conn    *net.UDPConn
	eventFd int
	peerID  uint64

	cipher *protocol.Cipher

	clientSendSequence uint64
	serverReplayWindow protocol.ReplayWindow
}

func (s *session) run(ctx context.Context) error {
	// initval, eventfd counter 초기값
	// EFD_CLOEXEC, exec 시 fd 자동 close
	// EFD_NONBLOCK, read/write가 block되지 않게 함
	eventFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("failed to Eventfd: %v", err)
	}
	defer unix.Close(eventFd)

	s.eventFd = eventFd

	errGroup, errCtx := errgroup.WithContext(ctx)

	context.AfterFunc(errCtx, func() {
		// eventFd에 1증가 write
		var eventBuf [8]byte
		binary.NativeEndian.PutUint64(eventBuf[:], 1)
		if _, err := unix.Write(eventFd, eventBuf[:]); err != nil {
			log.Printf("failed to write eventfd (AfterFunc): %v", err)
		}

		// udp connection 종료 (tun은 Cleanup에서 처리)
		if err := s.conn.Close(); err != nil {
			log.Printf("failed to udp close: %v", err)
		}
	})
	errGroup.Go(func() error {
		if err := s.udpToTun(errCtx); err != nil {
			return fmt.Errorf("failed to UDP to TUN: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := s.tunToUdp(errCtx); err != nil {
			return fmt.Errorf("failed to TUN To UDP: %w", err)
		}
		return nil
	})
	errGroup.Go(func() error {
		if err := s.keepAliveLoop(errCtx); err != nil {
			return fmt.Errorf("failed to keep alive loop: %w", err)
		}
		return nil
	})

	err = errGroup.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}

func (sess *session) udpToTun(ctx context.Context) error {
	buf := make([]byte, protocol.MessageHeaderLen+protocol.MaxPayloadSize+protocol.AEADTagLen)
	for {
		n, err := sess.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n > 0 {
			packet, err := sess.cipher.DecodePacket(buf[:n], protocol.DirectionServerToClient)
			if err != nil {
				return err
			}
			if packet.Type != protocol.MessageTypeData {
				return fmt.Errorf("unexpected message type: expected=%d actual=%d", protocol.MessageTypeData, packet.Type)
			}
			if err := sess.acceptServerSequence(packet.Sequence); err != nil {
				continue
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

func (sess *session) tunToUdp(ctx context.Context) error {
	buf := make([]byte, protocol.MaxPayloadSize)
	for {
		n, err := sess.tun.ReadContext(ctx, buf, sess.eventFd)
		if err != nil {
			return err
		}
		if n > 0 {
			message := protocol.Message{
				Header: protocol.Header{
					Type:     protocol.MessageTypeData,
					PeerID:   sess.peerID,
					Sequence: sess.nextSendSequence(),
				},
				Payload: buf[:n],
			}
			packet, err := sess.cipher.EncodePacket(&message, protocol.DirectionClientToServer)
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

func (sess *session) keepAliveLoop(ctx context.Context) error {
	ticker := time.NewTicker(defaultKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			message := protocol.Message{
				Header: protocol.Header{
					Type:     protocol.MessageTypeKeepalive,
					PeerID:   sess.peerID,
					Sequence: sess.nextSendSequence(),
				},
			}
			packet, err := sess.cipher.EncodePacket(&message, protocol.DirectionClientToServer)
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
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (sess *session) nextSendSequence() uint64 {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	sess.clientSendSequence++
	return sess.clientSendSequence
}

func (sess *session) acceptServerSequence(seq uint64) error {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if err := sess.serverReplayWindow.Accept(seq); err != nil {
		return fmt.Errorf("server sequence rejected: sequence=%d: %w", seq, err)
	}

	return nil
}
