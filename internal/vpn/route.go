package vpn

import (
	"elevpn/internal/netlink"
	"errors"
	"fmt"
	"net"
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
	ip4 := net.ParseIP(r.spec.ServerIP).To4()
	gateway := net.ParseIP(r.spec.Gateway).To4()
	if ip4 == nil || gateway == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	ifa, err := net.InterfaceByName(r.spec.RealOIFName)
	if err != nil {
		return err
	}

	if err := netlink.RestoreDefaultRoute(gateway, ifa.Index); err != nil {
		return err
	}

	if err := netlink.DelHostRoute(ip4, gateway, ifa.Index); err != nil {
		return err
	}

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
	gateway := net.ParseIP(spec.Gateway).To4()
	if ip4 == nil || gateway == nil {
		return fmt.Errorf("only IPv4 is supported")
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

	if err := netlink.AddHostRoute(ip4, gateway, ifa.Index); err != nil {
		return err
	}

	if err := netlink.ReplaceDefaultRoute(tunIfa.Index); err != nil {
		return err
	}

	return nil
}
