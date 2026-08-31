package vpn

import (
	"elevpn/internal/netlink"
	"net"
)

type routeOperations interface {
	addHostRoute(ip, gateway net.IP, ifIndex int) error
	delHostRoute(ip, gateway net.IP, ifIndex int) error
	replaceDefaultRoute(ifIndex int) error
	restoreDefaultRoute(gateway net.IP, ifIndex int) error
}

var _ routeOperations = netlinkRouteOperations{}

type netlinkRouteOperations struct{}

func (netlinkRouteOperations) addHostRoute(ip, gateway net.IP, ifIndex int) error {
	return netlink.AddHostRoute(ip, gateway, ifIndex)
}

func (netlinkRouteOperations) delHostRoute(ip, gateway net.IP, ifIndex int) error {
	return netlink.DelHostRoute(ip, gateway, ifIndex)
}

func (netlinkRouteOperations) replaceDefaultRoute(ifIndex int) error {
	return netlink.ReplaceDefaultRoute(ifIndex)
}

func (netlinkRouteOperations) restoreDefaultRoute(gateway net.IP, ifIndex int) error {
	return netlink.RestoreDefaultRoute(gateway, ifIndex)
}
