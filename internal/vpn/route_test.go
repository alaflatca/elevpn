package vpn

import (
	"errors"
	"net"
	"testing"
)

var _ routeOperations = (*fakeRouteOperations)(nil)

type fakeRouteOperations struct {
	addCalls []net.IP
	delCalls []net.IP

	addErrorAt int
	addError   error

	delErrorAt int
	delError   error

	replaceCalls int
	replaceError error

	restoreCalls int
	restoreError error
}

func (f *fakeRouteOperations) addHostRoute(ip, gateway net.IP, ifIndex int) error {
	f.addCalls = append(f.addCalls, ip)

	if f.addErrorAt > 0 && len(f.addCalls) == f.addErrorAt {
		return f.addError
	}

	return nil
}

func (f *fakeRouteOperations) delHostRoute(ip, gateway net.IP, ifIndex int) error {
	f.delCalls = append(f.delCalls, ip)

	if f.delErrorAt > 0 && len(f.delCalls) == f.delErrorAt {
		return f.delError
	}

	return nil
}

func (f *fakeRouteOperations) replaceDefaultRoute(ifIndex int) error {
	f.replaceCalls++
	return f.replaceError
}

func (f *fakeRouteOperations) restoreDefaultRoute(gateway net.IP, ifIndex int) error {
	f.restoreCalls++
	return f.restoreError
}

func TestRouteApplyFailsOnFirstBypass(t *testing.T) {
	addErr := errors.New("add host route failed")

	fakeOps := &fakeRouteOperations{
		addErrorAt: 1,
		addError:   addErr,
	}

	route, err := NewRoute(RouteSpec{
		ServerRouteIP:        "198.51.100.10",
		Gateway:              "127.0.0.1",
		GatewayInterfaceName: "lo",
		TunnelInterfaceName:  "lo", // tun?
		BypassCIDRs: []string{
			"198.51.100.10/32",
			"203.0.113.20/32",
		},
	})
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	route.ops = fakeOps

	err = route.Apply()
	if err == nil {
		t.Fatal("expected route apply to fail")
	}
	if !errors.Is(err, addErr) {
		t.Fatalf("expected add route error, got: %v", err)
	}

	if got := len(fakeOps.addCalls); got != 1 {
		t.Fatalf("expected one add attempt, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 0 {
		t.Fatalf("expected no rollback attempts, got: %d", got)
	}
	if fakeOps.replaceCalls != 0 {
		t.Fatalf("expected no default route replacement attempts, got: %d", fakeOps.replaceCalls)
	}
}

func TestRouteApplyRollsBackAfterPartialFailure(t *testing.T) {
	addErr := errors.New("add host route failed")

	fakeOps := &fakeRouteOperations{
		addErrorAt: 2,
		addError:   addErr,
	}

	route, err := NewRoute(RouteSpec{
		ServerRouteIP:        "198.51.100.10",
		Gateway:              "127.0.0.1",
		GatewayInterfaceName: "lo",
		TunnelInterfaceName:  "lo", // tun?
		BypassCIDRs: []string{
			"198.51.100.10/32",
			"203.0.113.20/32",
		},
	})
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	route.ops = fakeOps

	err = route.Apply()
	if err == nil {
		t.Fatal("expected route apply to fail")
	}
	if !errors.Is(err, addErr) {
		t.Fatalf("expected add route error, got: %v", err)
	}

	if got := len(fakeOps.addCalls); got != 2 {
		t.Fatalf("expected two add attempts, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 1 {
		t.Fatalf("expected one rollback attempt, got: %d", got)
	}

	wantRollbackIP := net.ParseIP("198.51.100.10").To4()
	if !fakeOps.delCalls[0].Equal(wantRollbackIP) {
		t.Fatalf("expected rollback IP %s, got: %s", wantRollbackIP, fakeOps.delCalls[0])
	}

	if fakeOps.replaceCalls != 0 {
		t.Fatalf("expected no default route replacement attempts, got: %d", fakeOps.replaceCalls)
	}
}

func TestRouteApplyRollsBackOnDefaultRouteFailure(t *testing.T) {
	replaceErr := errors.New("replace default route failed")

	fakeOps := &fakeRouteOperations{
		replaceError: replaceErr,
	}

	route, err := NewRoute(RouteSpec{
		ServerRouteIP:        "198.51.100.10",
		Gateway:              "127.0.0.1",
		GatewayInterfaceName: "lo",
		TunnelInterfaceName:  "lo", // tun?
		BypassCIDRs: []string{
			"198.51.100.10/32",
			"203.0.113.20/32",
		},
	})
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	route.ops = fakeOps

	err = route.Apply()
	if err == nil {
		t.Fatal("expected route apply to fail")
	}
	if !errors.Is(err, replaceErr) {
		t.Fatalf("expected replace route error, got: %v", err)
	}

	if got := len(fakeOps.addCalls); got != 2 {
		t.Fatalf("expected two add attempts, got: %d", got)
	}
	if got := fakeOps.replaceCalls; got != 1 {
		t.Fatalf("expected one default route replacement attempt, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 2 {
		t.Fatalf("expected two rollback attempts, got: %d", got)
	}

	wantRollbackIPs := []net.IP{
		net.ParseIP("203.0.113.20").To4(),
		net.ParseIP("198.51.100.10").To4(),
	}

	for i, want := range wantRollbackIPs {
		if !fakeOps.delCalls[i].Equal(want) {
			t.Fatalf("expected rollback IP %s at index %d, got: %s", want, i, fakeOps.delCalls[i])
		}
	}
}

func TestRouteApplyJoinsRollbackError(t *testing.T) {
	addErr := errors.New("add host route failed")
	delErr := errors.New("delete host route failed")

	fakeOps := &fakeRouteOperations{
		addErrorAt: 3,
		addError:   addErr,
		delErrorAt: 1,
		delError:   delErr,
	}

	route, err := NewRoute(RouteSpec{
		ServerRouteIP:        "198.51.100.10",
		Gateway:              "127.0.0.1",
		GatewayInterfaceName: "lo",
		TunnelInterfaceName:  "lo", // tun?
		BypassCIDRs: []string{
			"198.51.100.10/32",
			"203.0.113.20/32",
			"192.0.2.30/32",
		},
	})
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	route.ops = fakeOps

	err = route.Apply()
	if err == nil {
		t.Fatal("expected route apply to fail")
	}

	if !errors.Is(err, addErr) {
		t.Fatalf("expected add route error, got: %v", err)
	}
	if !errors.Is(err, delErr) {
		t.Fatalf("expected rollback delete route error, got: %v", err)
	}

	if got := len(fakeOps.addCalls); got != 3 {
		t.Fatalf("expected three add attempts, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 2 {
		t.Fatalf("expected two rollback attempts, got: %d", got)
	}

	wantRollbackIPs := []net.IP{
		net.ParseIP("203.0.113.20").To4(),
		net.ParseIP("198.51.100.10").To4(),
	}

	for i, want := range wantRollbackIPs {
		if !fakeOps.delCalls[i].Equal(want) {
			t.Fatalf("expected rollback IP %s at index %d, got: %s", want, i, fakeOps.delCalls[i])
		}
	}
}

func TestRouteApplySucceeds(t *testing.T) {
	fakeOps := &fakeRouteOperations{}

	route, err := NewRoute(RouteSpec{
		ServerRouteIP:        "198.51.100.10",
		Gateway:              "127.0.0.1",
		GatewayInterfaceName: "lo",
		TunnelInterfaceName:  "lo", // tun?
		BypassCIDRs: []string{
			"198.51.100.10/32",
			"203.0.113.20/32",
		},
	})
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	route.ops = fakeOps

	err = route.Apply()
	if err != nil {
		t.Fatalf("expected route apply to succeed, got: %v", err)
	}

	if got := len(fakeOps.addCalls); got != 2 {
		t.Fatalf("expected two add attempts, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 0 {
		t.Fatalf("expected no rollback attempts, got: %d", got)
	}
	if got := fakeOps.replaceCalls; got != 1 {
		t.Fatalf("expected one default route replacement attempt, got: %d", got)
	}

}
