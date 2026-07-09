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
	spec                RouteSpec
	serverRouteIP       net.IP
	gateway             net.IP
	gatewayInterfaceIdx int
	tunnelInterfaceIdx  int
}

func NewRoute(spec RouteSpec) (*Route, error) {
	r := &Route{spec: spec}
	if err := r.validate(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Route) Name() string {
	return "Route"
}

func (r *Route) Cleanup() error {
	// ip route del <server_ip>/32 via <real_gateway> dev <real_nic>
	// if err := netlink.RestoreDefaultRoute(r.gateway, r.gatewayInterfaceIdx); err != nil {
	// 	return err
	// }
	// ip route replace default via <real_gateway> dev <real_nic>
	if err := netlink.DelHostRoute(r.serverRouteIP, r.gateway, r.gatewayInterfaceIdx); err != nil {
		return err
	}
	return nil
}

func (r *Route) Apply() error {
	if err := r.resolve(); err != nil {
		return err
	}
	// ip route add <server_ip>/32 via <real_gateway> dev <real_nic>
	if err := netlink.AddHostRoute(r.serverRouteIP, r.gateway, r.gatewayInterfaceIdx); err != nil {
		return err
	}
	// ip route replace default dev <tun_nic>
	// if err := netlink.ReplaceDefaultRoute(r.tunnelInterfaceIdx); err != nil {
	// 	if delErr := netlink.DelHostRoute(r.serverRouteIP, r.gateway, r.gatewayInterfaceIdx); delErr != nil {
	// 		return fmt.Errorf("failed to replace default route: %v (failed to rollback host route: %v)", err, delErr)
	// 	}
	// 	return fmt.Errorf("failed to replace default route: %v", err)
	// }
	return nil
}

func (r *Route) validate() error {
	if r.spec.ServerRouteIP == "" {
		return errors.New("server route ip is empty")
	}
	if r.spec.Gateway == "" {
		return errors.New("gateway is empty")
	}
	if r.spec.GatewayInterfaceName == "" {
		return errors.New("real oif name is empty")
	}
	if r.spec.TunnelInterfaceName == "" {
		return errors.New("tun oif name is empty")
	}
	return nil
}

func (r *Route) resolve() error {
	r.serverRouteIP = net.ParseIP(r.spec.ServerRouteIP).To4()
	r.gateway = net.ParseIP(r.spec.Gateway).To4()
	if r.serverRouteIP == nil || r.gateway == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	gatewayIfa, err := net.InterfaceByName(r.spec.GatewayInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to interface by name(%q): %v", r.spec.GatewayInterfaceName, err)
	}
	if gatewayIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", r.spec.GatewayInterfaceName)
	}
	r.gatewayInterfaceIdx = gatewayIfa.Index

	tunnelIfa, err := net.InterfaceByName(r.spec.TunnelInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to interface by name(%q): %v", r.spec.TunnelInterfaceName, err)
	}
	if tunnelIfa.Index < 0 {
		return fmt.Errorf("invalid %q interface index", r.spec.TunnelInterfaceName)
	}
	r.tunnelInterfaceIdx = tunnelIfa.Index

	return nil
}
