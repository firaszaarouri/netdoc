package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RPKI per-prefix Route Origin Authorization (ROA) lookup. Uses Team Cymru's
// DNS-based RPKI service — the same provider we use for ASN lookups. For
// each resolved IP, we query:
//
//   <reversed-prefix>.<asn>.rpki.cymru.com TXT
//
// Response is "VALID", "INVALID", "UNKNOWN", or empty. We surface per-IP
// RPKI status; INVALID is a routing-security flag (the route announcement
// doesn't match published ROA data).
//
// Reference: https://team-cymru.com/community-services/ip-asn-mapping/
//
// internet.nl exposes RPKI per-prefix as part of its web + mail tests;
// netdoc joins it as one of the only CLI tools doing this.

// rpkiStatus is the per-IP ROA verdict.
type rpkiStatus struct {
	IP     string `json:"ip"`
	Status string `json:"status"` // VALID / INVALID / UNKNOWN
}

// rpkiResult aggregates per-IP status.
type rpkiResult struct {
	Attempted bool         `json:"attempted"`
	Statuses  []rpkiStatus `json:"statuses,omitempty"`
}

// probeRPKIAll queries Team Cymru's RPKI service for every resolved IP.
// Requires the per-IP ASN to already be known (we use the same map the
// DNS check populates).
func probeRPKIAll(ips []net.IP, asns map[string]asnInfo, transport *dnsTransport, timeout time.Duration) rpkiResult {
	out := rpkiResult{Attempted: true}
	if len(ips) == 0 {
		return out
	}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	out.Statuses = make([]rpkiStatus, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		info, ok := asns[ip.String()]
		if !ok {
			out.Statuses[i] = rpkiStatus{IP: ip.String(), Status: "UNKNOWN"}
			continue
		}
		wg.Add(1)
		go func(idx int, ip net.IP, asn, prefix string) {
			defer wg.Done()
			out.Statuses[idx] = rpkiStatus{
				IP:     ip.String(),
				Status: queryRPKIStatus(ip, asn, prefix, transport, timeout),
			}
		}(i, ip, info.ASN, info.Prefix)
	}
	wg.Wait()
	return out
}

// queryRPKIStatus issues the Team Cymru CHAOS TXT query for one prefix.
func queryRPKIStatus(ip net.IP, asn, prefix string, transport *dnsTransport, timeout time.Duration) string {
	if asn == "" || prefix == "" {
		return "UNKNOWN"
	}
	// Reverse the prefix for the DNS label. For "140.82.121.0/24" we
	// build "0.121.82.140.<mask>.<asn>.rpki.cymru.com".
	v4 := ip.To4()
	if v4 == nil {
		return "UNKNOWN" // IPv6 RPKI via Cymru not as well documented; skip.
	}
	// Use a /24 derived prefix for simplicity — Cymru returns the most
	// specific covering ROA.
	qname := fmt.Sprintf("%d.%d.%d.%d.%s.rpki.cymru.com",
		v4[3], v4[2], v4[1], v4[0], asn)
	rrs, err := queryDNS(qname, dns.TypeTXT, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return "UNKNOWN"
	}
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			combined := concat(txt.Txt)
			combined = trimAndUpper(combined)
			if combined == "VALID" || combined == "INVALID" || combined == "UNKNOWN" {
				return combined
			}
			// Some responses use other formats; pass through.
			return combined
		}
	}
	return "UNKNOWN"
}

func concat(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p
	}
	return out
}

func trimAndUpper(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c = c - 32
		}
		out = append(out, c)
	}
	return string(out)
}

// rpkiHeadline returns "RPKI: 3/3 VALID" or "RPKI: 1 INVALID" depending.
func rpkiHeadline(r rpkiResult) string {
	if !r.Attempted || len(r.Statuses) == 0 {
		return ""
	}
	valid, invalid, unknown := 0, 0, 0
	for _, s := range r.Statuses {
		switch s.Status {
		case "VALID":
			valid++
		case "INVALID":
			invalid++
		default:
			unknown++
		}
	}
	if invalid > 0 {
		return "RPKI INVALID: " + itoa(invalid) + "/" + itoa(len(r.Statuses))
	}
	if valid > 0 && unknown == 0 {
		return "RPKI: " + itoa(valid) + "/" + itoa(len(r.Statuses)) + " VALID"
	}
	if valid > 0 {
		return "RPKI: " + itoa(valid) + " VALID, " + itoa(unknown) + " unknown"
	}
	return ""
}
