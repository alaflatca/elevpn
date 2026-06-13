package netlink

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"golang.org/x/sys/unix"
)

func GetDefaultExternalInterface() (string, error) {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)

	externalInterface, err := getDefaultExternalInterface(fd)
	if err != nil {
		return "", err
	}

	return externalInterface, nil
}

func getDefaultExternalInterface(fd int) (string, error) {
	rtmsg := newBaseRtmsg()
	header := rtgen(rtmsg)
	packet := nlMsg(1, unix.RTM_GETROUTE, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, header)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return "", err
	}

	ifr, err := recvRoutesAck(fd, 1)
	if err != nil {
		return "", err
	}

	return ifr, nil
}

// unix.NLM_F_DUMP 플래그는 커널에서 "경로가 너무 많으니 여러 번 나눠서 보냄"
// 마지막에 Type = 3 (NLMSG_DONE)  메세지를 하나 보냄
func recvRoutesAck(fd int, want uint32) (string, error) {
	if err := setSocketTimeout(fd, 1); err != nil {
		return "", err
	}

	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR { // EINTR == interrupt
				continue
			}
			// EAGAIN = Error AGAIN
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return "", fmt.Errorf("netlink response timeout: 커널 응답이 업습니다.")
			}
			if err == unix.ENOBUFS {
				return "", fmt.Errorf("netlink receive buffer overflow: 데이터 유실가능성")
			}
			return "", fmt.Errorf("recvfrom fatal error: %w", err)
		}

		// 최소한 넷링크 헤더(16)는 읽을 수 있는 길이어야함
		pos := 0
		for pos+unix.NLMSG_HDRLEN <= n {
			// Nelink Header 읽기
			msgLength := binary.NativeEndian.Uint32(buf[pos : pos+4])
			msgType := binary.NativeEndian.Uint16(buf[pos+4 : pos+6])
			// flags 생략,  msgFlags := binary.NativeEndian.Uint16(buf[pos+6 : pos+8])
			msgSeq := binary.NativeEndian.Uint32(buf[pos+8 : pos+12])
			// portID 생략, msgPortID := binary.NativeEndian.Uint32(buf[pos+12 : pos+16])

			nextMsgPos := pos + align4(int(msgLength))

			if msgSeq != want {
				pos = nextMsgPos
				continue
			}

			switch msgType {
			case unix.NLMSG_DONE: // NLM_F_DUMP ---> NLMSG_DONE(끝났음을 의미)
				return "", fmt.Errorf("default external interface not found in routing table ")
			case unix.NLMSG_ERROR:
				return "", fmt.Errorf("nlmsg error: %v", msgType)
			case 24:
				endPos := pos + int(msgLength)

				// 디폴트 인터페이스 구별
				dstLen := buf[pos+17] // 목적지 ip의 prefix 0 ~ 32
				table := buf[pos+20]  // 메인 라우팅 테이블

				if dstLen != 0 || table != 254 {
					break
				}

				pos += 28 //   Route Header 패스
				for pos+4 <= endPos {
					attrLength := binary.NativeEndian.Uint16(buf[pos : pos+2])
					attrType := binary.NativeEndian.Uint16(buf[pos+2 : pos+4])

					if attrLength < 4 || pos+int(attrLength) > endPos {
						break
					}
					attrValue := buf[pos+4 : pos+int(attrLength)]

					if attrType == unix.RTA_OIF {
						if len(attrValue) < 4 {
							log.Printf("attr value is short: %v", len(attrValue))
							continue
						}

						ifindex := binary.NativeEndian.Uint32(attrValue)
						ifr, err := net.InterfaceByIndex(int(ifindex))
						if err != nil {
							log.Printf("invalid interface by index: %v", ifindex)
							continue
						}
						log.Printf("found external interface : %+v", ifr) // 아직 정확히 external interface 를 찾은게 아님 따로 구별 하는 로직이있어야함 임시
						return ifr.Name, nil
					}
					if attrType == unix.RTA_GATEWAY {
						if len(attrValue) < 4 {
							log.Printf("attr value is short: %v", len(attrValue))
							continue
						}
						gateway := net.IP(attrValue).String()
					}

					pad := align4(int(attrLength))
					pos += pad
				}
			}
			pos = nextMsgPos
		}
	}
}

func setSocketTimeout(fd int, sec int64) error {
	tv := &unix.Timeval{
		Sec:  sec,
		Usec: 0,
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, tv); err != nil {
		return fmt.Errorf("failed to socket timeout: %w", err)
	}
	return nil
}
