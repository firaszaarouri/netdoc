package main

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// IPv6 flow-label-based ECMP-aware traceroute. RFC 6437 / RFC 6438
// stipulate that IPv6 routers SHOULD use the 20-bit flow-label field for
// ECMP load balancing. By varying the flow-label across probes we can
// discover ECMP path variants without raw sockets — unlike IPv4 Paris
// traceroute which requires raw-socket access to UDP checksum or IP-ID
// fields.
//
// The Go runtime exposes flow-label control via
// golang.org/x/net/ipv6.ControlMessage.FlowLabel which IS unprivileged on
// Linux + macOS (the kernel accepts IPV6_FLOWINFO_SEND for SOCK_DGRAM
// sockets). Windows IPv6 stack does not expose flow-label setting through
// Winsock — IPv6 ECMP traceroute is therefore Linux/macOS-only.
//
// netdoc surfaces:
//   - Number of distinct paths observed (by hop-at-TTL-N comparison across
//     flow labels)
//   - Per-flow path: TTL-by-TTL IP list
//   - "ECMP visible" verdict when ≥2 distinct paths observed at the same TTL
//
// On Windows or when the target has no IPv6, the probe returns
// Attempted=false silently.

// flowLabelResult records the verdict.
type flowLabelResult struct {
	Attempted    bool          `json:"attempted"`
	FlowsProbed  int           `json:"flows_probed,omitempty"`
	DistinctPaths int          `json:"distinct_paths,omitempty"`
	ECMPVisible  bool          `json:"ecmp_visible,omitempty"`
	Paths        [][]hopResult `json:"paths,omitempty"`
}

// probeIPv6ECMP runs traceroutes with N different flow labels and reports
// path divergence. Returns Attempted=false on Windows, no-IPv6 targets,
// or when the OS doesn't accept IPV6_FLOWINFO_SEND.
func probeIPv6ECMP(target net.IP, maxHops int, timeout time.Duration) flowLabelResult {
	out := flowLabelResult{Attempted: true}
	if target.To4() != nil {
		out.Attempted = false
		return out
	}
	// Test by attempting a single flow-labeled probe; if it fails outright
	// we mark Attempted=false rather than reporting bogus results.
	if !flowLabelSupported(target, timeout) {
		out.Attempted = false
		return out
	}

	// Use 5 distinct flow labels — enough to expose ECMP without spamming.
	flowLabels := []uint32{0x10001, 0x20002, 0x30003, 0x40004, 0x50005}
	out.FlowsProbed = len(flowLabels)
	out.Paths = make([][]hopResult, len(flowLabels))
	var wg sync.WaitGroup
	for i, fl := range flowLabels {
		wg.Add(1)
		go func(idx int, flow uint32) {
			defer wg.Done()
			out.Paths[idx] = traceRouteIPv6Flow(target, maxHops, flow, timeout)
		}(i, fl)
	}
	wg.Wait()

	// Count distinct path signatures (concatenated hop IPs per flow).
	sigs := make(map[string]bool)
	for _, p := range out.Paths {
		var ips []string
		for _, h := range p {
			ips = append(ips, h.IP)
		}
		sort.Strings(ips)
		sigs[strings.Join(ips, ",")] = true
	}
	out.DistinctPaths = len(sigs)
	out.ECMPVisible = out.DistinctPaths >= 2
	return out
}

// traceRouteIPv6Flow runs a TTL=1..maxHops traceroute over IPv6, fixing
// the flow label across all probes at this TTL series. Returns the
// observed path.
//
// Implementation note: we delegate per-TTL probing to a platform-specific
// helper that uses ControlMessage.FlowLabel where available. The helper
// returns nil on platforms without flow-label support (Windows).
func traceRouteIPv6Flow(target net.IP, maxHops int, flow uint32, timeout time.Duration) []hopResult {
	if maxHops <= 0 {
		maxHops = 30
	}
	hops := make([]hopResult, 0, maxHops)
	for ttl := 1; ttl <= maxHops; ttl++ {
		h := probeIPv6FlowTTL(target, ttl, flow, timeout)
		h.TTL = ttl
		hops = append(hops, h)
		if h.Reached {
			break
		}
	}
	// Concurrent reverse DNS.
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].IP == "" {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(ctx, hops[idx].IP); err == nil && len(names) > 0 {
				hops[idx].Name = strings.TrimSuffix(names[0], ".")
			}
		}(i)
	}
	wg.Wait()
	return hops
}

// flowLabelSupported tries one probe to detect runtime support. Returns
// true on success. Implementation lives in path_ipv6_flowlabel_unix.go
// and path_ipv6_flowlabel_windows.go.

// ecmpHeadline returns "ECMP IPv6: 3 paths" when divergence is visible.
func ecmpHeadline(r flowLabelResult) string {
	if !r.Attempted {
		return ""
	}
	if !r.ECMPVisible {
		return "" // single path — clean, don't crowd the line
	}
	return "ECMP IPv6: " + itoa(r.DistinctPaths) + " paths observed"
}
