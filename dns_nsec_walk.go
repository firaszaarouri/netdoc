package main

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// NSEC zone-walking. For DNSSEC-signed zones that use NSEC (RFC 4034) rather
// than NSEC3 (RFC 5155), an attacker can enumerate the entire zone by
// chaining NEXT pointers. Every NXDOMAIN response includes an NSEC record
// proving the absence by saying "there is no name between X and Y" — and
// Y is the NEXT name in canonical order. By chaining queries we collect
// every name in the zone.
//
// netdoc surfaces this as a security finding: when a zone uses unhashed
// NSEC and walking succeeds, the zone's contents are publicly enumerable.
// Most modern zones use NSEC3 specifically to prevent this. Some old or
// niche zones (research, internal) still use NSEC.
//
// We cap the walk at MAX_WALK_HOPS to avoid runaway time/memory on huge
// zones. Even a partial walk demonstrates the vulnerability.
//
// References:
//   RFC 4034 §5 (NSEC RRset)
//   RFC 5155 (NSEC3 — defends against walking)
//   nmap dns-nsec-enum, fierce, ldns-walk are prior art.

const maxNSECWalkHops = 50

// nsecWalkResult is the outcome of a walk attempt.
type nsecWalkResult struct {
	Attempted    bool     `json:"attempted"`
	ZoneUsesNSEC bool     `json:"zone_uses_nsec"`     // false → NSEC3 or unsigned
	NamesFound   []string `json:"names_found,omitempty"`
	Hops         int      `json:"hops"`
	Truncated    bool     `json:"truncated"`          // hit maxNSECWalkHops cap
}

// walkZoneNSEC attempts to enumerate `zone` via NSEC chain. Returns the
// names discovered. If the zone uses NSEC3 (or isn't signed), returns
// ZoneUsesNSEC=false silently.
func walkZoneNSEC(zone string, transport *dnsTransport, timeout time.Duration) nsecWalkResult {
	out := nsecWalkResult{Attempted: true}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	// Start by querying a guaranteed-absent name within the zone.
	curName := "z-walk-start-netdoc." + zone
	for hops := 0; hops < maxNSECWalkHops; hops++ {
		next, owner, found := queryNSECNext(curName, transport, timeout)
		if !found {
			break
		}
		if hops == 0 {
			out.ZoneUsesNSEC = true
		}
		owner = strings.TrimSuffix(strings.ToLower(owner), ".")
		next = strings.TrimSuffix(strings.ToLower(next), ".")
		if owner != "" && !strings.HasPrefix(owner, "z-walk-start") {
			// Don't include the synthetic probe name.
			out.NamesFound = appendUnique(out.NamesFound, owner)
		}
		if next == "" {
			break
		}
		// Did we wrap to the zone apex?
		if next == zone || next == zone+"." {
			break
		}
		// Move to the NEXT name and walk again.
		curName = next + ".a" // Append a label so NXDOMAIN is forced again
		out.Hops = hops + 1
	}
	if out.Hops >= maxNSECWalkHops {
		out.Truncated = true
	}
	return out
}

// queryNSECNext sends a query expecting NXDOMAIN and returns the NEXT
// owner name + the NSEC owner from the response. Returns (next, owner,
// found-an-NSEC-record).
func queryNSECNext(name string, transport *dnsTransport, timeout time.Duration) (string, string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit so we get DNSSEC records

	resp, err := dnsExchange(m, transport, timeout)
	if err != nil || resp == nil {
		return "", "", false
	}
	if resp.Rcode != dns.RcodeNameError && resp.Rcode != dns.RcodeSuccess {
		return "", "", false
	}
	for _, rr := range resp.Ns {
		if n, ok := rr.(*dns.NSEC); ok {
			return n.NextDomain, n.Hdr.Name, true
		}
	}
	return "", "", false
}

// nsecWalkHeadline returns the security finding for the hint line.
func nsecWalkHeadline(r nsecWalkResult) string {
	if !r.ZoneUsesNSEC || len(r.NamesFound) == 0 {
		return ""
	}
	suffix := ""
	if r.Truncated {
		suffix = "+"
	}
	return "NSEC walk: " + itoa(len(r.NamesFound)) + suffix + " names exposed"
}
