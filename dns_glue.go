package main

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Glue-record presence check (DNSViz parity). For in-bailiwick NS records
// (e.g. ns1.example.com being a nameserver FOR example.com), the parent
// zone MUST publish glue records — A/AAAA records for those NS in the
// parent's NS RRset — or resolution chicken-and-eggs. Missing glue is a
// lameness-class delegation problem.
//
// Out-of-bailiwick NS (ns1.example.net for example.com) don't require glue
// because the resolver can find ns1.example.net through normal recursion.
//
// Our probe: for each NS that's a subdomain of the zone, query the parent's
// nameservers for an A record of that NS hostname and report whether glue
// was returned in the Additional section.

// glueResult records one NS's glue-record status.
type glueResult struct {
	NS           string   `json:"ns"`
	InBailiwick  bool     `json:"in_bailiwick"`
	HasGlue      bool     `json:"has_glue"`
	GlueIPv4     []string `json:"glue_ipv4,omitempty"`
	GlueIPv6     []string `json:"glue_ipv6,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// checkGlue evaluates glue posture for every NS of `zone`. Returns one
// result per NS; out-of-bailiwick NS report InBailiwick=false and HasGlue
// is not meaningful for them (we set it true to avoid false-positive alarms).
func checkGlue(zone string, nameservers []string, timeout time.Duration) []glueResult {
	if len(nameservers) == 0 {
		return nil
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	// Find the parent nameservers: walk up one label.
	parent := parentZone(zone)
	parentNS := findParentNS(parent, timeout)
	if len(parentNS) == 0 {
		// Couldn't get parent NS — abort silently rather than misreport.
		return nil
	}
	parentAddr := parentNS[0] + ":53"

	results := make([]glueResult, len(nameservers))
	var wg sync.WaitGroup
	for i, ns := range nameservers {
		wg.Add(1)
		go func(idx int, nsHost string) {
			defer wg.Done()
			results[idx] = checkOneGlue(zone, nsHost, parentAddr, timeout)
		}(i, ns)
	}
	wg.Wait()
	return results
}

func checkOneGlue(zone, nsHost, parentAddr string, timeout time.Duration) glueResult {
	r := glueResult{NS: nsHost}
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	host := strings.TrimSuffix(strings.ToLower(nsHost), ".")
	// In-bailiwick iff the NS is a subdomain (or equals) the zone we delegate.
	r.InBailiwick = strings.HasSuffix(host, "."+zone) || host == zone
	if !r.InBailiwick {
		// Out-of-bailiwick — glue not required. Mark HasGlue=true so the
		// summary won't flag it as a problem.
		r.HasGlue = true
		return r
	}
	// Query the parent's NS for the zone's NS record with EDNS0. Glue,
	// when present, appears in the Additional section.
	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	msg.RecursionDesired = false
	msg.SetEdns0(4096, false)
	resp, _, err := client.Exchange(msg, parentAddr)
	if err != nil || resp == nil {
		r.Error = "could not query parent"
		return r
	}
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			if strings.EqualFold(strings.TrimSuffix(v.Hdr.Name, "."), host) {
				r.GlueIPv4 = append(r.GlueIPv4, v.A.String())
			}
		case *dns.AAAA:
			if strings.EqualFold(strings.TrimSuffix(v.Hdr.Name, "."), host) {
				r.GlueIPv6 = append(r.GlueIPv6, v.AAAA.String())
			}
		}
	}
	r.HasGlue = len(r.GlueIPv4) > 0 || len(r.GlueIPv6) > 0
	return r
}

// parentZone returns the immediate parent of a zone: example.com -> com.
// Returns "." (root) for TLDs.
func parentZone(zone string) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	idx := strings.IndexByte(zone, '.')
	if idx < 0 {
		return "."
	}
	return zone[idx+1:]
}

// findParentNS gets an authoritative NS hostname for `parent` zone by asking
// a root resolver. Returns the first NS we resolve to an IP address (we need
// the IP to query directly).
func findParentNS(parent string, timeout time.Duration) []string {
	if parent == "." {
		// Use a hardcoded root NS — a.root-servers.net.
		return []string{"198.41.0.4"}
	}
	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(parent), dns.TypeNS)
	msg.RecursionDesired = true
	// Use Cloudflare's recursive — fast + reliable.
	resp, _, err := client.Exchange(msg, "1.1.1.1:53")
	if err != nil || resp == nil {
		return nil
	}
	var nsHosts []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsHosts = append(nsHosts, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	// Resolve the first NS hostname to an IP so we can query directly.
	for _, h := range nsHosts {
		ips, err := net.LookupHost(h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				return []string{ip}
			}
		}
	}
	return nil
}

// glueHeadline returns "glue: missing for ns1.x — break-glass!" for the
// hint line, but only when there's a real problem. Healthy posture is silent.
func glueHeadline(results []glueResult) string {
	missing := 0
	for _, r := range results {
		if r.InBailiwick && !r.HasGlue {
			missing++
		}
	}
	if missing == 0 {
		return ""
	}
	if missing == 1 {
		// Surface the specific NS name.
		for _, r := range results {
			if r.InBailiwick && !r.HasGlue {
				return "missing glue: " + r.NS
			}
		}
	}
	return "missing glue on " + itoa(missing) + " NS"
}
