package vpn

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type RouteSpec struct {
	ServerIP    string
	Gateway     string
	RealOIFName string
	TunOIFName  string
}

type Route struct {
	spec         RouteSpec
	oldDefaultGw string
}

func NewRoute(spec RouteSpec) *Route {
	return &Route{spec: spec}
}

func (r *Route) Name() string {
	return "Route"
}

func (r *Route) Apply() error {
	return SetRoute(r.spec)
}

func (r *Route) Cleanup() error {
	return nil
}

func UnsetRoute() error {
	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	defer unix.Close(fd)
	return nil
}

func SetRoute(spec RouteSpec) error {
	if spec.ServerIP == "" {
		return errors.New("server ip is empty")
	}
	if spec.Gateway == "" {
		return errors.New("gateway is empty")
	}
	if spec.RealOIFName == "" {
		return errors.New("real oif name is empty")
	}
	if spec.TunOIFName == "" {
		return errors.New("tun oif name is empty")
	}

	ip4 := net.ParseIP(spec.ServerIP).To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", spec.ServerIP)
	}

	gateway := net.ParseIP(spec.Gateway).To4()
	if gateway == nil {
		return fmt.Errorf("invalid gateway address: %s", spec.Gateway)
	}

	ifa, err := net.InterfaceByName(spec.RealOIFName)
	if err != nil {
		return err
	}
	if ifa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.RealOIFName)
	}

	tunIfa, err := net.InterfaceByName(spec.TunOIFName)
	if err != nil {
		return err
	}
	if tunIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.TunOIFName)
	}

	fd, err := openNetlink(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	defer unix.Close(fd)

	packet := buildAddHostRouteMsg(1, ip4, gateway, ifa.Index)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send rt: %w", err)
	}
	if err := recvAcks(fd, 1); err != nil {
		return err
	}

	packet = buildReplaceDefaultRouteMsg(2, tunIfa.Index)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send rt: %w", err)
	}
	if err := recvAcks(fd, 2); err != nil {
		return err
	}

	return nil
}
