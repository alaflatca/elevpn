//go:build darwin

package tun

import (
	"fmt"
	"strconv"
	"strings"
)

func Create(name string) (*Device, error) {
	// unit, err := parseUTUNName(name)
	// if err != nil {
	// 	return nil, err
	// }

	// fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	// if err != nil {
	// 	return nil, fmt.Errorf("socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL): %v", err)
	// }

	return nil, nil
}

func (d *Device) Setup(name string) error {
	return nil
}

func parseUTUNName(name string) (int, error) {
	if name == "" || name == "utun" {
		return -1, nil
	}

	if !strings.HasPrefix(name, "utun") {
		return 0, fmt.Errorf("darwin only supports utun names like utun0, utin1, ...: %q", name)
	}

	s := strings.TrimPrefix(name, "utun")
	if s == "" {
		return -1, nil
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid utun name: %q", name)
	}
	return n, nil
}
