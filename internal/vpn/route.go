package vpn

import (
	"elevpn/internal/netlink"
	"errors"
	"fmt"
	"net"
)

type RouteSpec struct {
	ServerRouteIP        string
	Gateway              string
	GatewayInterfaceName string
	TunnelInterfaceName  string
}

type Route struct {
	serverIP            net.IP
	serverRouteIP       net.IP
	gateway             net.IP
	gatewayInterfaceIdx int
	tunnelInterfaceIdx  int
}

func NewRoute(spec RouteSpec) *Route {
	r := &Route{}
	r.Normalize(spec)
	return r
}

func (r *Route) Name() string {
	return "Route"
}

func (r *Route) Normalize(spec RouteSpec) error {
	if spec.ServerRouteIP == "" {
		return errors.New("server ip is empty")
	}
	if spec.Gateway == "" {
		return errors.New("gateway is empty")
	}
	if spec.GatewayInterfaceName == "" {
		return errors.New("real oif name is empty")
	}
	if spec.TunnelInterfaceName == "" {
		return errors.New("tun oif name is empty")
	}

	serverIP, _, err := net.SplitHostPort(spec.ServerRouteIP)
	if err != nil {
		return fmt.Errorf("failed to split host, port: %v", err)
	}

	r.serverIP = net.ParseIP(serverIP).To4()
	r.serverRouteIP = net.ParseIP(spec.ServerRouteIP).To4()
	r.gateway = net.ParseIP(spec.Gateway).To4()

	if r.serverIP == nil || r.serverRouteIP == nil || r.gateway == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	gatewayIfa, err := net.InterfaceByName(spec.GatewayInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to interface by name(%q): %v", spec.GatewayInterfaceName, err)
	}
	if gatewayIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.GatewayInterfaceName)
	}
	r.gatewayInterfaceIdx = gatewayIfa.Index

	tunnelIfa, err := net.InterfaceByName(spec.TunnelInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to interface by name(%q): %v", spec.TunnelInterfaceName, err)
	}
	if tunnelIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", spec.TunnelInterfaceName)
	}
	r.tunnelInterfaceIdx = tunnelIfa.Index

	return nil
}

func (r *Route) Cleanup() error {
	if err := netlink.RestoreDefaultRoute(r.gateway, r.gatewayInterfaceIdx); err != nil {
		return err
	}
	if err := netlink.DelHostRoute(r.serverIP, r.gateway, r.gatewayInterfaceIdx); err != nil {
		return err
	}
	return nil
}

func (r *Route) Apply() error {
	if err := netlink.AddHostRoute(r.serverIP, r.gateway, r.gatewayInterfaceIdx); err != nil {
		return err
	}
	if err := netlink.ReplaceDefaultRoute(r.tunnelInterfaceIdx); err != nil {
		return err
	}
	return nil
}
