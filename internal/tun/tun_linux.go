//go:build linux

package tun

import (
	"fmt"
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

func (d *Device) Setup(name string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(sock)

	_, err = unix.NewIfreq(name)
	if err != nil {

	}

	return nil
}
