package main

import (
	"net"
	"time"
)

// IPv4 UDP traceroute via IP_RECVERR socket error queue.
//
// Why this exists alongside the existing ICMP traceroute and the
// TCP-source-port ECMP traceroute:
//
//   - Some upstream firewalls drop ICMP echo entirely → ICMP traceroute
//     reports "no hops" even though packets transit.
//   - Some firewalls drop outbound TCP SYNs to non-standard ports → TCP-
//     source-port traceroute fails for paths beyond the local NAT.
//   - UDP probes to high ports (33434+) are often permitted where the
//     other two are blocked — this is exactly the classical Van Jacobson
//     UDP traceroute trick, just driven from userspace via IP_RECVERR.
//
// We use connect()ed UDP sockets so the kernel routes ICMP errors per
// 4-tuple — same per-socket-queue trick as the TCP version, no quoted-
// packet correlation needed.
//
// Destination ports follow the classical traceroute convention: 33434
// base, incremented per TTL. When we reach the destination, it (almost
// always) sends ICMP Port Unreachable for these high random ports, which
// our error queue receives as ee_type=3 ee_code=3 with the destination
// as the offender — that's our "reached" signal.

// udpTraceResult records the verdict for the UDP traceroute pass.
type udpTraceResult struct {
	Attempted bool        `json:"attempted"`
	Reason    string      `json:"reason,omitempty"` // populated when Attempted=false
	Hops      []hopResult `json:"hops,omitempty"`
	Reached   bool        `json:"reached,omitempty"`
}

// probeIPv4UDPTraceroute runs the UDP traceroute. Returns Attempted=false
// on non-Linux platforms (no IP_RECVERR equivalent) or non-IPv4 targets.
func probeIPv4UDPTraceroute(target net.IP, maxHops int, timeout time.Duration) udpTraceResult {
	out := udpTraceResult{}
	if target == nil || target.To4() == nil {
		out.Reason = "target is not IPv4"
		return out
	}
	if !udpTracerouteSupported() {
		out.Reason = "platform does not support unprivileged UDP traceroute (needs IP_RECVERR — Linux only)"
		return out
	}
	return probeIPv4UDPTracerouteImpl(target, maxHops, timeout)
}

// udpTraceHeadline returns "UDP traceroute: N hops" when the UDP path
// shows different reachability than the ICMP path — empty otherwise to
// avoid line clutter for the common case where both agree.
func udpTraceHeadline(r udpTraceResult, icmpHopCount int) string {
	if !r.Attempted || len(r.Hops) == 0 {
		return ""
	}
	if r.Reached && icmpHopCount > 0 {
		// Both paths reach destination; UDP doesn't add news. Skip.
		return ""
	}
	if r.Reached && icmpHopCount == 0 {
		// UDP reached but ICMP didn't — actionable: ICMP is filtered upstream.
		return "UDP traceroute: " + itoa(len(r.Hops)) + " hops (ICMP filtered)"
	}
	// UDP didn't reach.
	return ""
}
