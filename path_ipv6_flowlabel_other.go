//go:build !linux && !darwin

package main

import (
	"net"
	"time"
)

// IPv6 flow-label ECMP traceroute is not available on this platform.
// Windows lacks IPV6_FLOWINFO_SEND through Winsock; FreeBSD etc. would
// need raw-socket access. These stubs return "not attempted" so the
// caller treats the platform as out-of-scope cleanly.

func flowLabelSupported(target net.IP, timeout time.Duration) bool {
	return false
}

func probeIPv6FlowTTL(target net.IP, ttl int, flow uint32, timeout time.Duration) hopResult {
	return hopResult{}
}
