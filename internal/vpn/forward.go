package vpn

import "os"

type IPForward struct {
	previousValue []byte
}

func NewIPForward() *IPForward {
	return &IPForward{}
}

func (f *IPForward) Apply() error {
	prev, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}

	f.previousValue = prev

	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

func (f *IPForward) Cleanup() error {
	if f.previousValue == nil {
		return nil
	}

	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", f.previousValue, 0644)
}

func (f *IPForward) Name() string {
	return "IPForward"
}
