package main

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS CHAOS-class queries — the nmap `dns-nsid` equivalent done properly. Every
// authoritative-DNS daemon (BIND, NSD, Knot, Unbound, PowerDNS, dnsmasq) traditionally
// answers CH-class TXT queries for three special names with its own software
// version / hostname / operator string:
//
//   version.bind     — server software + version (BIND, NSD, Knot, PowerDNS, ...)
//   hostname.bind    — physical hostname (anycast PoP identification)
//   id.server        — RFC 4892 modern operator-defined identifier
//
// Modern hardened deployments mask these (return REFUSED or a generic string),
// which is itself a posture signal. The probe is unauthenticated and lightweight
// — one UDP packet per (NS, name) pair.

// nsChaosResult is what we learned about one authoritative nameserver.
type nsChaosResult struct {
	NS            string `json:"ns"`
	VersionBind   string `json:"version_bind,omitempty"`
	HostnameBind  string `json:"hostname_bind,omitempty"`
	IDServer      string `json:"id_server,omitempty"`
}

// queryCHAOS asks one nameserver for the three CHAOS names. Returns whatever
// it learned; empty fields mean the NS refused, masked the response, or didn't
// answer.
func queryCHAOS(nsHost string, timeout time.Duration) nsChaosResult {
	r := nsChaosResult{NS: nsHost}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := nsHost
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	client := &dns.Client{Net: "udp", Timeout: timeout}

	r.VersionBind = chaosTXT(client, addr, "version.bind.")
	r.HostnameBind = chaosTXT(client, addr, "hostname.bind.")
	r.IDServer = chaosTXT(client, addr, "id.server.")
	return r
}

// chaosTXT sends a single CHAOS-class TXT query and returns the concatenated
// TXT-rdata strings, or "" on any failure / empty answer.
func chaosTXT(client *dns.Client, addr, name string) string {
	msg := &dns.Msg{}
	msg.SetQuestion(name, dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS
	msg.RecursionDesired = false

	resp, _, err := client.Exchange(msg, addr)
	if err != nil || resp == nil {
		return ""
	}
	if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeNameError {
		return ""
	}
	var parts []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if s != "" {
					parts = append(parts, s)
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

// queryCHAOSAll issues CHAOS queries against a list of nameservers in parallel
// and returns the per-server results. Empty input or all-failures returns nil.
func queryCHAOSAll(nameservers []string, timeout time.Duration) []nsChaosResult {
	if len(nameservers) == 0 {
		return nil
	}
	// Cap at 8 NS to avoid the rare zone with dozens of NS records.
	if len(nameservers) > 8 {
		nameservers = nameservers[:8]
	}
	results := make([]nsChaosResult, len(nameservers))
	var wg sync.WaitGroup
	for i, ns := range nameservers {
		wg.Add(1)
		go func(idx int, nsHost string) {
			defer wg.Done()
			results[idx] = queryCHAOS(nsHost, timeout)
		}(i, ns)
	}
	wg.Wait()
	// Filter out results where every field is empty.
	var keep []nsChaosResult
	for _, r := range results {
		if r.VersionBind != "" || r.HostnameBind != "" || r.IDServer != "" {
			keep = append(keep, r)
		}
	}
	return keep
}

// chaosHeadline returns a short human-friendly summary of the CHAOS responses
// for the second hint line. Empty when no result is interesting.
func chaosHeadline(results []nsChaosResult) string {
	if len(results) == 0 {
		return ""
	}
	// Group by version_bind so we don't repeat "BIND 9.18.24" five times when
	// every NS runs the same software.
	versions := make(map[string]int)
	for _, r := range results {
		v := r.VersionBind
		if v == "" {
			v = r.IDServer
		}
		if v != "" {
			versions[v]++
		}
	}
	if len(versions) == 0 {
		return ""
	}
	var parts []string
	for v, count := range versions {
		if count > 1 {
			parts = append(parts, v+" ×"+itoa(count))
		} else {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(buf[i:])
}
