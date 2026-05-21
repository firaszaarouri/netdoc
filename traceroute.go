package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// hopResult is the recorded result for a single traceroute hop.
type hopResult struct {
	TTL       int     `json:"ttl"`
	IP        string  `json:"ip,omitempty"`
	Name      string  `json:"name,omitempty"`
	RTTms     float64 `json:"rtt_ms,omitempty"`     // average across probes
	MinRTTms  float64 `json:"min_rtt_ms,omitempty"` // mtr-style min
	MaxRTTms  float64 `json:"max_rtt_ms,omitempty"` // mtr-style max
	JitterMs  float64 `json:"jitter_ms,omitempty"` // mean absolute deviation from avg
	LossPct   int     `json:"loss_pct,omitempty"`  // % of probes that didn't return
	Sent      int     `json:"sent,omitempty"`      // probes sent at this TTL
	Reached   bool    `json:"reached,omitempty"`
	ASN       string  `json:"asn,omitempty"`     // e.g. "AS36459"
	ASNOrg    string  `json:"asn_org,omitempty"` // e.g. "GitHub, Inc."
	ASNCC     string  `json:"asn_cc,omitempty"`  // e.g. "US"
	rtt       time.Duration                       // average — used by hint rendering
}

// probesPerHop controls how many ICMP echoes we send per TTL. mtr does N
// continuous; we do this in one shot. 3 probes keeps the run fast while
// giving real loss/jitter signal.
const probesPerHop = 3

// traceRoute probes ICMP echo at TTLs 1..maxHops in parallel, with
// probesPerHop probes at each TTL aggregated into per-hop min/avg/max/
// jitter/loss statistics. Returns the path trimmed to the first hop that
// reached the destination. Each hop's IP is reverse-resolved concurrently.
func traceRoute(dest net.IP, maxHops int, timeout time.Duration) []hopResult {
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}

	type probeResult struct {
		ttl int
		hop hopResult
	}

	results := make(chan probeResult, maxHops)
	for ttl := 1; ttl <= maxHops; ttl++ {
		go func(t int) {
			results <- probeResult{ttl: t, hop: probeOneTTL(dest, t, perProbe)}
		}(ttl)
	}

	hops := make([]hopResult, maxHops)
	for i := 0; i < maxHops; i++ {
		pr := <-results
		pr.hop.TTL = pr.ttl
		hops[pr.ttl-1] = pr.hop
	}

	// Trim to the first hop that actually reached the destination — TTLs
	// beyond it would just hit the destination again on a fresh probe.
	final := maxHops
	for i, h := range hops {
		if h.Reached {
			final = i + 1
			break
		}
	}
	hops = hops[:final]

	// Concurrent best-effort reverse DNS for hop IPs.
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

// probeOneTTL sends probesPerHop ICMP echoes at the given TTL and aggregates
// the results into a single hopResult with min/avg/max/jitter/loss. The IP
// is the first responding hop (other probes may return slightly different
// IPs under ECMP — we keep the first to stabilize the report).
func probeOneTTL(dest net.IP, ttl int, perProbe time.Duration) hopResult {
	var h hopResult
	h.Sent = probesPerHop
	var rtts []time.Duration
	for i := 0; i < probesPerHop; i++ {
		ip, rtt, reached, err := pingICMPWithTTL(dest, ttl, perProbe)
		if err != nil {
			continue
		}
		if h.IP == "" {
			h.IP = ip.String()
		}
		rtts = append(rtts, rtt)
		if reached {
			h.Reached = true
		}
	}
	if len(rtts) == 0 {
		h.LossPct = 100
		return h
	}
	h.LossPct = int(float64(probesPerHop-len(rtts)) / float64(probesPerHop) * 100)
	// min / max / sum
	minRTT, maxRTT, sum := rtts[0], rtts[0], time.Duration(0)
	for _, r := range rtts {
		if r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		sum += r
	}
	avg := sum / time.Duration(len(rtts))
	h.rtt = avg
	h.RTTms = ms(avg)
	h.MinRTTms = ms(minRTT)
	h.MaxRTTms = ms(maxRTT)
	// Jitter — mean absolute deviation from avg.
	var dev time.Duration
	for _, r := range rtts {
		diff := r - avg
		if diff < 0 {
			diff = -diff
		}
		dev += diff
	}
	h.JitterMs = ms(dev / time.Duration(len(rtts)))
	return h
}
