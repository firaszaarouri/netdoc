package main

import (
	"net"
	"time"
)

// IPv4 ECMP-aware traceroute via TCP source-port variation.
//
// Equal-Cost Multi-Path (RFC 2992, RFC 7424) routers hash the 5-tuple
// (proto, src-ip, dst-ip, src-port, dst-port) to choose the next hop.
// Varying the source port across probe groups discovers ECMP path variants.
// This is the IPv4 analogue of the IPv6 flow-label trick — same goal,
// different mechanism.
//
// The classic ICMP-echo traceroute (traceroute.go) keeps the same 5-tuple
// for every probe, so it always traverses the same ECMP path. By
// sending TCP SYNs with N distinct source ports, each port-family
// traverses a (potentially) different ECMP branch.
//
// Platform support:
//
//   - Linux: full implementation via IP_RECVERR socket error queue (the
//     same technique tracepath(8) uses for unprivileged traceroute). The
//     kernel routes ICMP Time Exceeded responses for TCP packets through
//     the originating socket's error queue, which userspace reads with
//     recvmsg(MSG_ERRQUEUE). NO raw-socket capability required.
//
//   - macOS: not implemented unprivileged. macOS has no IP_RECVERR
//     equivalent and SOCK_DGRAM ICMP is restricted to echo/echo-reply
//     types, so we can't intercept Time Exceeded responses without
//     raw-socket access (Administrator). The macOS user still gets
//     IPv6 flow-label ECMP traceroute when the target has AAAA.
//
//   - Windows: not implemented unprivileged. IcmpSendEcho is ICMP-only,
//     and raw ICMP receive requires Administrator. Same brand-coherence
//     call as macOS — leave it stubbed.
//
// References:
//   RFC 2992 — Analysis of an Equal-Cost Multi-Path Algorithm
//   RFC 7424 — Mechanisms for Optimizing Link Aggregation Group and
//              Equal Cost Multipath Load Balancing
//   tracepath(8) source — uses IP_RECVERR for unprivileged path discovery
//   linux kernel net/ipv4/ip_sockglue.c — IP_RECVERR delivery

// tcpECMPResult records the verdict from the TCP-source-port ECMP probe.
type tcpECMPResult struct {
	Attempted     bool          `json:"attempted"`
	DstPort       int           `json:"dst_port,omitempty"`
	PortsProbed   int           `json:"ports_probed,omitempty"`
	DistinctPaths int           `json:"distinct_paths,omitempty"`
	ECMPVisible   bool          `json:"ecmp_visible,omitempty"`
	Paths         [][]hopResult `json:"paths,omitempty"`
	Reason        string        `json:"reason,omitempty"` // populated when Attempted=false
}

// probeIPv4ECMPTCP runs the TCP-source-port traceroute. Returns
// Attempted=false on non-Linux platforms or non-IPv4 targets, with a
// human-readable Reason for the JSON consumer.
func probeIPv4ECMPTCP(target net.IP, dstPort, maxHops int, timeout time.Duration) tcpECMPResult {
	out := tcpECMPResult{DstPort: dstPort}
	if target == nil || target.To4() == nil {
		out.Reason = "target is not IPv4"
		return out
	}
	if !tcpSourcePortTraceSupported() {
		out.Reason = "platform does not support unprivileged TCP-source-port traceroute (needs IP_RECVERR — Linux only)"
		return out
	}
	return probeIPv4ECMPTCPImpl(target, dstPort, maxHops, timeout)
}

// tcpECMPHeadline returns a short headline string when ECMP path
// divergence is visible, otherwise empty.
func tcpECMPHeadline(r tcpECMPResult) string {
	if !r.Attempted || !r.ECMPVisible {
		return ""
	}
	return "ECMP IPv4: " + itoa(r.DistinctPaths) + " paths via TCP-source-port"
}
