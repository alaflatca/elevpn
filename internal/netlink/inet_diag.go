package netlink

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

func GetEstablishedTCPRemoteIPsByLocalPort(port uint16) ([]netip.Addr, error) {
	fd, err := openNetlink(unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return []netip.Addr{}, err
	}
	defer unix.Close(fd)

	remoteIPs, err := getEstablishedTcpRemoteIP(fd, port)
	if err != nil {
		return []netip.Addr{}, err
	}
	return remoteIPs, nil
}

const (
	tcpEstablished = 1
)

type inetDiagReqV2 struct {
	family   byte
	protocol byte
	ext      byte
	pad      byte
	states   uint32
	sockid   [48]byte
}

func newInetDiagReqV2() inetDiagReqV2 {
	return inetDiagReqV2{
		family:   unix.AF_INET,
		protocol: unix.IPPROTO_TCP,
		states:   1 << tcpEstablished, //2
	}
}

func buildInetDiagReqV2(req inetDiagReqV2) []byte {
	b := make([]byte, 56)

	b[0] = req.family
	b[1] = req.protocol
	b[2] = req.ext
	b[3] = req.pad
	binary.NativeEndian.PutUint32(b[4:8], req.states)
	copy(b[8:56], req.sockid[:])

	return b
}

func getEstablishedTcpRemoteIP(fd int, port uint16) ([]netip.Addr, error) {
	req := newInetDiagReqV2()
	payload := buildInetDiagReqV2(req)
	packet := nlMsg(1, unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, payload)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return []netip.Addr{}, err
	}

	result, err := recvEstablishedTCPRemoteIP(fd, 1, port)
	if err != nil {
		return []netip.Addr{}, err
	}

	return result, nil
}

func recvEstablishedTCPRemoteIP(fd int, want uint32, port uint16) ([]netip.Addr, error) {
	if err := setSocketTimeout(fd, 1); err != nil {
		return []netip.Addr{}, err
	}

	var result []netip.Addr
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return []netip.Addr{}, fmt.Errorf("netlink response timeout: 커널 응답이 업습니다.")
			}
			if err == unix.ENOBUFS {
				return []netip.Addr{}, fmt.Errorf("netlink receive buffer overflow: 데이터 유실가능성")
			}
			return []netip.Addr{}, fmt.Errorf("recvfrom failed: %w", err)
		}

		pos := 0
		for pos+unix.NLMSG_HDRLEN <= n {
			msgLength := binary.NativeEndian.Uint32(buf[pos : pos+4])
			if msgLength < unix.NLMSG_HDRLEN {
				return []netip.Addr{}, fmt.Errorf("invalid netlink message length: msg_len=%d header_len=%d", msgLength, unix.NLMSG_HDRLEN)
			}
			msgType := binary.NativeEndian.Uint16(buf[pos+4 : pos+6])
			msgSeq := binary.NativeEndian.Uint32(buf[pos+8 : pos+12])

			nextMsgPos := pos + align4(int(msgLength))
			if nextMsgPos > n {
				return []netip.Addr{}, fmt.Errorf("truncated netlink message: next_pos=%d recv_len=%d msg_len=%d", nextMsgPos, n, msgLength)
			}

			if msgSeq != want {
				pos = nextMsgPos
				continue
			}

			switch msgType {
			case unix.NLMSG_DONE:
				if len(result) == 0 {
					return []netip.Addr{}, nil
				}
				return result, nil
			case unix.NLMSG_ERROR:
				if msgLength < unix.NLMSG_HDRLEN+4 {
					return nil, fmt.Errorf("short NLMSG_ERROR")
				}
				errno := int32(binary.NativeEndian.Uint32(buf[pos+unix.NLMSG_HDRLEN : pos+unix.NLMSG_HDRLEN+4]))
				if errno != 0 {
					return nil, fmt.Errorf("netlink errno=%d (%v)", -errno, unix.Errno(-errno))
				}
			case unix.SOCK_DIAG_BY_FAMILY:
				payloadStart := pos + unix.NLMSG_HDRLEN
				payloadEnd := pos + int(msgLength)
				payload := buf[payloadStart:payloadEnd]
				if len(payload) >= 28 {
					family := payload[0]
					state := payload[1]

					sourcePort := binary.BigEndian.Uint16(payload[4:6])
					var remoteIPByte [4]byte
					copy(remoteIPByte[:], payload[24:28])

					if family == unix.AF_INET && state == tcpEstablished && sourcePort == port {
						result = append(result, netip.AddrFrom4(remoteIPByte))
					}
				}
			}
			pos = nextMsgPos
		}
	}
}
