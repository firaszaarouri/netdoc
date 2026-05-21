package main

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Lame-delegation detection. A nameserver is "lame" for a zone when it
// answers queries (so DNS resolves through it sometimes) but does NOT
// claim authority — the AA bit isn't set, or its SOA differs from the
// authoritative SOA. Lame delegations cause sporadic resolution failures,
// resolver caching of wrong answers, and incident escalations.
//
// Probe model: for each NS listed in the zone's NS RRset, send an SOA
// query DIRECTLY to that NS (port 53, no recursion). Check:
//   - AA bit is set in the response (authoritative)
//   - SOA serial matches the consensus serial (everyone agrees what's current)
//
// Disagreement on either signals lameness. We report which NS is lame and
// why.
//
// References:
//   https://www.dns-oarc.net/sites/default/files/Lame-NS-presentation.pdf
//   nmap dns-nsec-enum is loosely related but tackles a different problem.

// lameNSResult records the verdict per NS.
type lameNSResult struct {
	NS              string `json:"ns"`
	Reachable       bool   `json:"reachable"`
	Authoritative   bool   `json:"authoritative"` // AA bit set
	SOASerial       uint32 `json:"soa_serial,omitempty"`
	IsLame          bool   `json:"is_lame,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// checkLameDelegation queries every NS for SOA of the zone and compares.
func checkLameDelegation(zone string, nameservers []string, timeout time.Duration) []lameNSResult {
	if len(nameservers) == 0 {
		return nil
	}
	if len(nameservers) > 8 {
		nameservers = nameservers[:8]
	}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	results := make([]lameNSResult, len(nameservers))
	var wg sync.WaitGroup
	for i, ns := range nameservers {
		wg.Add(1)
		go func(idx int, nsHost string) {
			defer wg.Done()
			results[idx] = probeOneLameNS(zone, nsHost, timeout)
		}(i, ns)
	}
	wg.Wait()
	// Determine consensus serial — the SOA serial that the majority of
	// reachable+AA-set NS agreed on.
	counts := make(map[uint32]int)
	for _, r := range results {
		if r.Authoritative && r.SOASerial > 0 {
			counts[r.SOASerial]++
		}
	}
	var consensus uint32
	maxCount := 0
	for s, c := range counts {
		if c > maxCount {
			consensus = s
			maxCount = c
		}
	}
	// Flag any NS that's unreachable, non-AA, or has a different SOA serial.
	for i := range results {
		r := &results[i]
		switch {
		case !r.Reachable:
			r.IsLame = true
			r.Reason = "unreachable"
		case !r.Authoritative:
			r.IsLame = true
			r.Reason = "AA bit not set"
		case r.SOASerial == 0:
			r.IsLame = true
			r.Reason = "no SOA"
		case consensus != 0 && r.SOASerial != consensus:
			r.IsLame = true
			r.Reason = "SOA serial mismatch (" + uint32str(r.SOASerial) + " vs consensus " + uint32str(consensus) + ")"
		}
	}
	return results
}

// probeOneLameNS sends a non-recursive SOA query to one NS and parses
// the response.
func probeOneLameNS(zone, nsHost string, timeout time.Duration) lameNSResult {
	r := lameNSResult{NS: nsHost}
	addr := nsHost
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	msg.RecursionDesired = false
	resp, _, err := client.Exchange(msg, addr)
	if err != nil || resp == nil {
		return r
	}
	r.Reachable = true
	r.Authoritative = resp.Authoritative
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			r.SOASerial = soa.Serial
			break
		}
	}
	// Some servers put SOA in Authority section.
	if r.SOASerial == 0 {
		for _, ans := range resp.Ns {
			if soa, ok := ans.(*dns.SOA); ok {
				r.SOASerial = soa.Serial
				break
			}
		}
	}
	return r
}

// lameDelegationHeadline returns "lame: <count> NS" or empty when healthy.
func lameDelegationHeadline(results []lameNSResult) string {
	lame := 0
	for _, r := range results {
		if r.IsLame {
			lame++
		}
	}
	if lame == 0 {
		return ""
	}
	return "lame delegation: " + itoa(lame) + " NS"
}

func uint32str(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + byte(v%10)
		v /= 10
	}
	return string(buf[i:])
}
