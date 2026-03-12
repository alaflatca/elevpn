//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func Create(name string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %v", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("new ifreq: %v", err)
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl(TUNSETIFF): %v", err)
	}

	actualName := ifr.Name()
	f := os.NewFile(uintptr(fd), "/dev/net/tun")

	return &Device{
		File: f,
		Name: actualName,
	}, nil
}

func (d *Device) SetMasquerade() error {
	socket, err := unix.Socket(unix.AF_NETLINK, unix.NETLINK_NETFILTER, 0)
	if err != nil {
		fmt.Errorf("socket: %w", err)
	}
	return nil
}

func (d *Device) SetIPv4CIDR(cidr string) error {
	if d == nil {
		return fmt.Errorf("nil device")
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR is supported: %q", cidr)
	}

	mask4 := net.IP(ipnet.Mask).To4()
	if mask4 == nil {
		return fmt.Errorf("invalid IPv4 mask in CIDR: %q", cidr)
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_INET, SOCK_DGRAM): %w", err)
	}
	defer unix.Close(sock)

	// TUN 인터페이스에 IPv4 추가
	ifr, err := unix.NewIfreq(d.Name)
	if err != nil {
		return fmt.Errorf("new ifreq(addr): %w", err)
	}
	if err := ifr.SetInet4Addr(ip4); err != nil {
		return fmt.Errorf("SetInet4Addr(addr): %w", err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFADDR): %w", err)
	}

	// TUN 인터페이스에  Subnet Mask 추가
	ifr, err = unix.NewIfreq(d.Name)
	if err != nil {
		return fmt.Errorf("new ifreq(mask): %w", err)
	}
	if err := ifr.SetInet4Addr(mask4); err != nil {
		return fmt.Errorf("SetInet4Addr(mask): %w", err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFNETMASK, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFNETMASK): %w", err)
	}

	return nil
}

func (d *Device) SetUp() error {
	if d == nil {
		return fmt.Errorf("nil device")
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(sock)

	ifr, err := unix.NewIfreq(d.Name)
	if err != nil {
		return fmt.Errorf("new ifreq: %w", err)
	}

	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SICOCGIFFLAGS: %w", err)
	}

	flags := ifr.Uint16()
	ifr.SetUint16(flags | unix.IFF_UP) // 기존 플래그에서  IFF_UP 플래그 추가

	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SICOCSIFFLAGS: %w", err)
	}

	return nil
}
