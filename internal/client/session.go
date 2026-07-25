package client

import (
	"elevpn/internal/tun"
	"net"
)

type tunnelSession struct {
	tun     *tun.Tun
	conn    *net.UDPConn
	eventFd int
	peerID  uint64
}
