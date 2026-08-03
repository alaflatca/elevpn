package client

import (
	"elevpn/internal/netlink"
	"log"
)

func detectSSHClientCIDRs(port uint16) ([]string, bool) {
	remoteIPs, err := netlink.GetEstablishedTCPRemoteIPsByLocalPort(port)
	if err != nil {
		return []string{}, false
	}

	result := []string{}
	seenCIDRs := map[string]bool{}

	for _, remoteIP := range remoteIPs {
		if !remoteIP.Is4() {
			return []string{}, false
		}
		cidr := remoteIP.String() + "/32"
		if seenCIDRs[cidr] {
			continue
		}
		seenCIDRs[cidr] = true
		result = append(result, cidr)
	}

	return result, true
}

func buildBypassCIDRs(serverRouteCIDR string) []string {
	bypassCIDRs := []string{serverRouteCIDR}
	sshClientCIDR, ok := detectSSHClientCIDRs(22)
	if ok {
		bypassCIDRs = append(bypassCIDRs, sshClientCIDR...)
	}

	log.Printf("[route] detected ssh bypass cidrs=%v", bypassCIDRs)
	return bypassCIDRs
}
