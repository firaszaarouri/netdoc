//go:build !linux

package main

import (
	"net"
	"time"
)

// Non-Linux stub for IPv4 UDP traceroute.
//
// Same constraint as path_tcp_traceroute_other.go: macOS and Windows
// lack IP_RECVERR, so receiving ICMP errors for non-raw sockets requires
// admin/root. The unprivileged single-binary brand promise stays intact —
// macOS users still have:
//   - existing ICMP traceroute (works on macOS via SOCK_DGRAM ICMP)
//   - IPv6 flow-label ECMP traceroute (works on macOS unprivileged)
// and Windows users still have:
//   - existing ICMP traceroute (works via IcmpSendEcho)

func udpTracerouteSupported() bool { return false }

func probeIPv4UDPTracerouteImpl(target net.IP, maxHops int, timeout time.Duration) udpTraceResult {
	return udpTraceResult{
		Attempted: false,
		Reason:    "Linux-only (uses IP_RECVERR socket error queue)",
	}
}
