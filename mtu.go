package main

import (
	"net"
	"time"
)

// commonMTUs lists real-world Path-MTU candidate values in descending order.
// Iterated from the top down — the first success becomes the lower bound for
// a follow-up binary search that pins the exact threshold.
//
//   1500 — standard Ethernet / cable / fiber
//   1492 — PPPoE (ADSL/VDSL)
//   1480 — IPv4 over GRE tunnel
//   1400 — common conservative VPN
//   1280 — IPv6 minimum
//    576 — legacy IPv4 minimum reassembly buffer
//
// 28-byte overhead per probe = 20 IPv4 header + 8 ICMP echo header.
var commonMTUs = []int{1500, 1492, 1480, 1400, 1280, 576}

const mtuOverhead = 28

// mtuProbe sends one DF-bit ICMP echo with the given total-MTU value and
// reports success. Silent drops (no reply at all) and explicit fragmentation-
// needed responses both count as "too big".
func mtuProbe(target net.IP, mtu int, timeout time.Duration) bool {
	status, _, err := pingICMPSized(target, mtu-mtuOverhead, true, timeout)
	return err == nil && status == 0
}

// detectPathMTU finds the largest packet size that traverses the path to
// target without fragmenting, using DF-bit ICMP probes. Returns the MTU in
// bytes or 0 if every probe failed. Windows-only — the non-Windows stub for
// pingICMPSized returns an error that detectPathMTU treats as "all failed",
// yielding 0 with no further work.
//
// Algorithm: descending sweep through commonMTUs to find an upper-bound
// success and a lower-bound failure, then binary search between them to
// pin the threshold. Typical 1500-MTU paths return after one probe.
func detectPathMTU(target net.IP, timeout time.Duration) int {
	perProbe := timeout
	if perProbe > 1500*time.Millisecond {
		perProbe = 1500 * time.Millisecond
	}

	foundMTU := 0
	smallestFail := 0
	for _, mtu := range commonMTUs {
		if mtuProbe(target, mtu, perProbe) {
			foundMTU = mtu
			break
		}
		smallestFail = mtu // remember the last failure for binary search bounds
	}
	if foundMTU == 0 {
		return 0
	}
	// If 1500 worked, we're done — Ethernet is the practical ceiling.
	if smallestFail == 0 || foundMTU >= 1500 {
		return foundMTU
	}
	// Binary search [foundMTU+1, smallestFail-1] for the exact threshold.
	// 8-byte precision is more than enough (MTUs are usually 4-byte-aligned
	// or quirky-but-stable values) and keeps the probe count under ~8.
	low, high := foundMTU, smallestFail-1
	for high-low > 8 {
		mid := (low + high) / 2
		if mtuProbe(target, mid, perProbe) {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low
}
