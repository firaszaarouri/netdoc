package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// IPv6-MX reachability check. IPv6-only senders (mobile carriers, EU
// government CDNs, etc.) cannot deliver mail to MX hosts without AAAA
// records. For each MX we check AAAA presence plus an opportunistic
// TCP-25 connect; reachability is informational (port 25 is often
// egress-blocked) but AAAA presence is the scored dimension.

// mxIPv6Result is the per-MX IPv6 verdict.
type mxIPv6Result struct {
	MXHost    string `json:"mx_host"`
	HasAAAA   bool   `json:"has_aaaa"`
	Address   string `json:"address,omitempty"`
	Reachable bool   `json:"reachable,omitempty"`
	Note      string `json:"note,omitempty"`
}

// probeMXIPv6 checks each MX hostname for an AAAA record and attempts
// a TCP-25 connect (best-effort — many residential/corporate networks
// block outbound port 25, so non-reachable doesn't always mean broken).
func probeMXIPv6(mxHosts []string, transport *dnsTransport, timeout time.Duration) []mxIPv6Result {
	out := make([]mxIPv6Result, 0, len(mxHosts))
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}
	for _, mxHost := range mxHosts {
		host := strings.TrimSuffix(mxHost, ".")
		r := mxIPv6Result{MXHost: host}
		rrs, err := queryDNS(host, dns.TypeAAAA, transport, perProbe)
		if err != nil || len(rrs) == 0 {
			out = append(out, r)
			continue
		}
		for _, rr := range rrs {
			if a, ok := rr.(*dns.AAAA); ok && a.AAAA != nil {
				r.HasAAAA = true
				r.Address = a.AAAA.String()
				// Attempt a 25/tcp connect — opportunistic. Block on perProbe
				// at most; non-blocking failures are common (egress firewalls).
				addr := net.JoinHostPort(r.Address, strconv.Itoa(25))
				conn, dialErr := net.DialTimeout("tcp6", addr, perProbe)
				if dialErr == nil {
					_ = conn.Close()
					r.Reachable = true
				} else {
					r.Note = "AAAA present but 25/tcp not reachable from here"
				}
				break
			}
		}
		out = append(out, r)
	}
	return out
}

// mxIPv6Headline summarises the per-MX AAAA findings for the Mail hint.
func mxIPv6Headline(results []mxIPv6Result) string {
	if len(results) == 0 {
		return ""
	}
	withAAAA := 0
	reachable := 0
	for _, r := range results {
		if r.HasAAAA {
			withAAAA++
		}
		if r.Reachable {
			reachable++
		}
	}
	if withAAAA == 0 {
		return "IPv6-MX: none"
	}
	if withAAAA == len(results) {
		return "IPv6-MX ✓ all"
	}
	return "IPv6-MX " + strconv.Itoa(withAAAA) + "/" + strconv.Itoa(len(results))
}
