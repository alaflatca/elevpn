package vpn

import (
	"errors"
	"net"
	"testing"
)

func TestRouteCleanupSucceeds(t *testing.T) {
	fakeOps := &fakeRouteOperations{}

	route := Route{
		gateway:             net.ParseIP("127.0.0.1").To4(),
		gatewayInterfaceIdx: 1,
		bypassIPs: []net.IP{
			net.ParseIP("198.51.100.10").To4(),
			net.ParseIP("203.0.113.20").To4(),
		},
		ops: fakeOps,
	}

	err := route.Cleanup()
	if err != nil {
		t.Fatalf("expected route cleanup to succeed, got: %v", err)
	}

	if got := fakeOps.restoreCalls; got != 1 {
		t.Fatalf("expected one default route restore attempt, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 2 {
		t.Fatalf("expected two host route delete attempts, got: %d", got)
	}

	wantDeletedIPs := []net.IP{
		net.ParseIP("203.0.113.20").To4(),
		net.ParseIP("198.51.100.10").To4(),
	}

	for i, want := range wantDeletedIPs {
		if !fakeOps.delCalls[i].Equal(want) {
			t.Fatalf("expected deleted IP %s at index %d, got: %s", want, i, fakeOps.delCalls[i])
		}
	}
}

func TestRouteCleanupStopsWhenRestoreFails(t *testing.T) {
	restoreErr := errors.New("restore default route failed")

	fakeOps := fakeRouteOperations{
		restoreError: restoreErr,
	}

	route := Route{
		gateway:             net.ParseIP("127.0.0.1").To4(),
		gatewayInterfaceIdx: 1,
		bypassIPs: []net.IP{
			net.ParseIP("198.51.100.10").To4(),
			net.ParseIP("203.0.113.20").To4(),
		},
		ops: &fakeOps,
	}

	err := route.Cleanup()
	if err == nil {
		t.Fatal("expected route cleanup to fail")
	}

	if got := fakeOps.restoreCalls; got != 1 {
		t.Fatalf("expected one default route restore attempt, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 0 {
		t.Fatalf("expected no host route delete attempts, got: %d", got)
	}
	if !errors.Is(err, restoreErr) {
		t.Fatalf("expected restore route error, got: %v", err)
	}
}

func TestRouteCleanupContinuesAfterDeleteFailure(t *testing.T) {
	delErr := errors.New("delete host route failed")

	fakeOps := fakeRouteOperations{
		delErrorAt: 1,
		delError:   delErr,
	}

	route := Route{
		gateway:             net.ParseIP("127.0.0.1").To4(),
		gatewayInterfaceIdx: 1,
		bypassIPs: []net.IP{
			net.ParseIP("198.51.100.10").To4(),
			net.ParseIP("203.0.113.20").To4(),
		},
		ops: &fakeOps,
	}

	err := route.Cleanup()
	if err == nil {
		t.Fatal("expected route cleanup to fail")
	}
	if !errors.Is(err, delErr) {
		t.Fatalf("expected delete error, got: %v", err)
	}
	if got := fakeOps.restoreCalls; got != 1 {
		t.Fatalf("expected one default route restore attempt, got: %d", got)
	}
	if got := len(fakeOps.delCalls); got != 2 {
		t.Fatalf("expected two host route delete attempts, got: %d", got)
	}

	wantDeletedIPs := []net.IP{
		net.ParseIP("203.0.113.20").To4(),
		net.ParseIP("198.51.100.10").To4(),
	}

	for i, want := range wantDeletedIPs {
		if !fakeOps.delCalls[i].Equal(want) {
			t.Fatalf("expected deleted IP %s at index %d, got: %s", want, i, fakeOps.delCalls[i])
		}
	}
}
