package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaces(t *testing.T) {
	ifrs, err := net.Interfaces()
	require.NoError(t, err)

	for _, ifr := range ifrs {
		t.Log("ifr: ", ifr)
	}
}
