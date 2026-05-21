package main

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EDNS Client Subnet (ECS, RFC 7871) probe. The query carries a fake client
// subnet hint; an ECS-aware authoritative server (GeoDNS / CDN steering)
// returns answers tailored to that subnet. The diagnostic value: see what
// IPs your CDN steers a French / Japanese / etc. client to.
//
// Activated by the --ecs CLI flag; netdoc accepts any IPv4 CIDR
// (e.g. --ecs 1.2.3.0/24). For each, we issue an A query carrying that
// subnet and report the answer alongside the resolver's normal answer.
//
// dig has +subnet; we differ by AUTO-RUNNING and integrating with the rest
// of the report.

// ecsResult is one ECS query result.
type ecsResult struct {
	Subnet  string   `json:"subnet"`
	IPs     []string `json:"ips,omitempty"`
	RCode   string   `json:"rcode,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// probeECS issues an A query carrying an ECS hint and returns the result.
// The query goes through Cloudflare's 1.1.1.1 (it forwards ECS to
// authoritative servers that opt in).
func probeECS(host, subnetCIDR string, timeout time.Duration) ecsResult {
	r := ecsResult{Subnet: subnetCIDR}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		r.Error = "invalid CIDR: " + err.Error()
		return r
	}
	prefix, _ := ipNet.Mask.Size()
	family := uint16(1)
	if ipNet.IP.To4() == nil {
		family = 2
	}
	addr := ipNet.IP
	if family == 1 {
		addr = ipNet.IP.To4()
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.RecursionDesired = true

	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
	}
	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(prefix),
		SourceScope:   0,
		Address:       addr,
	}
	opt.Option = append(opt.Option, ecs)
	msg.Extra = append(msg.Extra, opt)

	client := &dns.Client{Net: "udp", Timeout: timeout}
	// Quad9 11 (9.9.9.11) forwards ECS; Cloudflare strips ECS for privacy.
	// Use Google 8.8.8.8 which preserves ECS to ECS-aware authoritatives.
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		r.Error = tidyErr(err)
		return r
	}
	r.RCode = dns.RcodeToString[resp.Rcode]
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			r.IPs = append(r.IPs, a.A.String())
		}
	}
	return r
}

// probeECSMultiple runs ECS probes for a set of subnets in parallel. The
// default subnet bouquet sweeps five geographically diverse /24 ranges
// drawn from RIR registrations: US (Comcast), DE (Telekom), JP (NTT),
// BR (Vivo), AU (Telstra). Picked for liveness + spread.
func probeECSMultiple(host string, subnets []string, timeout time.Duration) []ecsResult {
	if len(subnets) == 0 {
		return nil
	}
	out := make([]ecsResult, len(subnets))
	type indexed struct {
		idx int
		r   ecsResult
	}
	ch := make(chan indexed, len(subnets))
	for i, sn := range subnets {
		go func(idx int, subnet string) {
			ch <- indexed{idx: idx, r: probeECS(host, subnet, timeout)}
		}(i, sn)
	}
	for range subnets {
		v := <-ch
		out[v.idx] = v.r
	}
	return out
}

// defaultECSSubnets returns the geographically-diverse subnet bouquet used
// when --ecs is passed without a value. Each is a /24 from a different
// continent, sourced from RIR allocations to ISPs with broad consumer base.
var defaultECSSubnets = []string{
	"73.0.0.0/24",      // Comcast US
	"77.20.0.0/24",     // Deutsche Telekom DE
	"126.0.0.0/24",     // NTT JP
	"177.32.0.0/24",    // Vivo BR
	"58.84.0.0/24",     // Telstra AU
}

// ecsHeadline summarises ECS results for the hint line. "ECS: 3 distinct
// answer sets" when GeoDNS steering is visible; empty otherwise.
func ecsHeadline(results []ecsResult) string {
	if len(results) == 0 {
		return ""
	}
	seen := make(map[string]bool)
	for _, r := range results {
		seen[strings.Join(r.IPs, ",")] = true
	}
	if len(seen) <= 1 {
		return "" // no GeoDNS variation observed
	}
	return "ECS: " + itoa(len(seen)) + " distinct answer sets across " + itoa(len(results)) + " subnets"
}
