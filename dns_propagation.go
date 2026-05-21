package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Multi-resolver propagation view — the whatsmydns.net / dnschecker.org niche
// done locally. Fans out a single A-record query to ~12 well-known public
// resolvers in parallel and reports whether they agree.
//
// The diagnostic question this answers: "did my DNS change actually
// propagate?" Stale negative-cache entries, anycast PoP variance, GeoDNS
// drift — they all show up here. Our verdict aggregates the per-resolver
// answers into one of:
//
//   consistent — every resolver returned the same RRset (verified by sha256
//                of sorted-IP strings).
//   split      — resolvers disagree (CDN GeoDNS, A/B testing, partial
//                propagation, or a hijack).
//   partial    — some resolvers didn't answer at all (transport block).
//
// The CLI tools dig/kdig/doggo/q can query an individual resolver, but none
// fan out and aggregate. nmap NSE has nothing for this. Online tools (web
// UI only) require entering a domain into a form.

// publicResolver carries identity + endpoint for one well-known public DNS.
type publicResolver struct {
	Name string
	Addr string // host:port
}

// publicResolvers is the curated list. Chosen for global coverage + low
// rate-limit risk for a single-domain query. All speak DNS over UDP/53.
var publicResolvers = []publicResolver{
	{"Cloudflare", "1.1.1.1:53"},
	{"Cloudflare-2", "1.0.0.1:53"},
	{"Google", "8.8.8.8:53"},
	{"Google-2", "8.8.4.4:53"},
	{"Quad9", "9.9.9.9:53"},
	{"Quad9-ECS", "9.9.9.11:53"}, // Quad9 with ECS forwarding
	{"OpenDNS", "208.67.222.222:53"},
	{"AdGuard", "94.140.14.14:53"},
	{"AdGuard-2", "94.140.15.15:53"},
	{"NextDNS", "45.90.28.0:53"},
	{"CleanBrowsing", "185.228.168.9:53"},
	{"Mullvad", "194.242.2.2:53"},
	{"Yandex", "77.88.8.8:53"},
}

// propagationResult is one resolver's view of the target.
type propagationResult struct {
	Resolver string   `json:"resolver"`
	Addr     string   `json:"addr"`
	IPs      []string `json:"ips,omitempty"`
	Hash     string   `json:"hash,omitempty"`     // sha256 of sorted IPs, hex
	OK       bool     `json:"ok"`                 // got an answer
	RCode    string   `json:"rcode,omitempty"`    // NOERROR / NXDOMAIN / SERVFAIL / REFUSED
	Error    string   `json:"error,omitempty"`
	MS       float64  `json:"ms"`
}

// propagationVerdict aggregates the per-resolver results.
type propagationVerdict struct {
	Verdict       string              `json:"verdict"` // consistent | split | partial | failed
	ConsistentBuckets int             `json:"buckets"` // distinct answer-hash buckets
	ResolversAnswered int             `json:"answered"`
	ResolversTotal    int             `json:"total"`
	Results       []propagationResult `json:"results,omitempty"`
}

// probePropagation queries every resolver in publicResolvers for an A record
// of the target and returns the aggregated verdict.
func probePropagation(host string, timeout time.Duration) propagationVerdict {
	if timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	var wg sync.WaitGroup
	results := make([]propagationResult, len(publicResolvers))
	for i, r := range publicResolvers {
		wg.Add(1)
		go func(idx int, res publicResolver) {
			defer wg.Done()
			results[idx] = queryOneResolver(host, res, timeout)
		}(i, r)
	}
	wg.Wait()
	return aggregatePropagation(results)
}

// queryOneResolver sends an A query and parses the response into a result.
func queryOneResolver(host string, r publicResolver, timeout time.Duration) propagationResult {
	out := propagationResult{Resolver: r.Name, Addr: r.Addr}
	start := time.Now()
	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, r.Addr)
	out.MS = ms(time.Since(start))
	if err != nil {
		out.Error = tidyErr(err)
		return out
	}
	if resp == nil {
		out.Error = "no response"
		return out
	}
	out.RCode = dns.RcodeToString[resp.Rcode]
	if resp.Rcode != dns.RcodeSuccess {
		return out
	}
	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	sort.Strings(ips)
	out.IPs = ips
	out.OK = true
	if len(ips) > 0 {
		sum := sha256.Sum256([]byte(strings.Join(ips, ",")))
		out.Hash = hex.EncodeToString(sum[:8]) // 8-byte prefix is plenty for distinguishing
	}
	return out
}

// aggregatePropagation tallies per-hash buckets and renders the verdict.
func aggregatePropagation(results []propagationResult) propagationVerdict {
	v := propagationVerdict{Results: results, ResolversTotal: len(results)}
	buckets := make(map[string]int)
	for _, r := range results {
		if !r.OK {
			continue
		}
		v.ResolversAnswered++
		buckets[r.Hash]++
	}
	v.ConsistentBuckets = len(buckets)
	switch {
	case v.ResolversAnswered == 0:
		v.Verdict = "failed"
	case v.ConsistentBuckets == 0:
		v.Verdict = "failed"
	case v.ConsistentBuckets == 1 && v.ResolversAnswered == v.ResolversTotal:
		v.Verdict = "consistent"
	case v.ConsistentBuckets == 1:
		v.Verdict = "partial" // everyone who answered agreed, but some didn't answer
	default:
		v.Verdict = "split"
	}
	return v
}

// propagationHeadline returns a short human-friendly summary like
// "13/13 resolvers consistent" or "split: 11 saw A, 2 saw B" for the
// DNS check's second hint line. Empty when the verdict has no signal
// worth surfacing inline.
func propagationHeadline(v propagationVerdict) string {
	if v.ResolversTotal == 0 {
		return ""
	}
	switch v.Verdict {
	case "consistent":
		return v.itoaIntents()
	case "partial":
		return v.itoaIntents() + " (some no-answer)"
	case "split":
		// Count IPs per bucket so we can describe the split usefully.
		buckets := make(map[string]int)
		for _, r := range v.Results {
			if r.OK {
				buckets[r.Hash]++
			}
		}
		sizes := make([]int, 0, len(buckets))
		for _, n := range buckets {
			sizes = append(sizes, n)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(sizes)))
		var parts []string
		for _, n := range sizes {
			parts = append(parts, itoa(n))
		}
		return "split " + strings.Join(parts, "/") + " across " + itoa(v.ResolversTotal)
	case "failed":
		return "all resolvers failed"
	}
	return ""
}

// itoaIntents returns the "X/Y consistent" string used by both consistent
// and partial verdicts.
func (v propagationVerdict) itoaIntents() string {
	return itoa(v.ResolversAnswered) + "/" + itoa(v.ResolversTotal) + " consistent"
}

// uniqueAnswers returns the distinct IP sets the resolvers reported, with
// the count of resolvers that saw each. Used for JSON inspection of the
// split case.
func (v propagationVerdict) uniqueAnswers() map[string][]string {
	seen := make(map[string][]string)
	for _, r := range v.Results {
		if !r.OK {
			continue
		}
		key := strings.Join(r.IPs, ",")
		if _, ok := seen[key]; !ok {
			seen[key] = r.IPs
		}
	}
	// Convert: key (sorted IP list) → ip slice. Caller can inspect length
	// for "how many distinct answers" and content for "what were they".
	_ = net.IP{} // keep net import in case Go vet trims
	return seen
}
