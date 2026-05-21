//go:build !linux

package main

import (
	"net"
	"time"
)

// Non-Linux stub for TCP-source-port ECMP traceroute.
//
// Why this is Linux-only:
//
//   - macOS: No IP_RECVERR socket option. SOCK_DGRAM ICMP is restricted
//     to types 0/8 (echo/echo-reply) and does not deliver Time Exceeded
//     for TCP probes. Receiving ICMP errors for TCP requires SOCK_RAW
//     IPPROTO_ICMP, which needs root. The macOS user still gets the
//     IPv6 flow-label ECMP traceroute (path_ipv6_flowlabel_unix.go)
//     when the target has AAAA.
//
//   - Windows: IcmpSendEcho is ICMP-only and raw ICMP receive requires
//     Administrator. Same brand-coherence call — netdoc must remain a
//     single unprivileged binary; we leave this stubbed.
//
//   - FreeBSD/OpenBSD: same constraints as macOS.

func tcpSourcePortTraceSupported() bool { return false }

func probeIPv4ECMPTCPImpl(target net.IP, dstPort, maxHops int, timeout time.Duration) tcpECMPResult {
	return tcpECMPResult{
		Attempted: false,
		DstPort:   dstPort,
		Reason:    "Linux-only (uses IP_RECVERR socket error queue; macOS/Windows would require raw sockets)",
	}
}
