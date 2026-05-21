package main

import (
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DANE for SMTP per RFC 7672. For every MX hostname we query the TLSA
// record at _25._tcp.<mxhost> and classify by cert-usage:
//
//	0  PKIX-TA — cert chain anchored at a PKIX trust store (DANE assists)
//	1  PKIX-EE — leaf cert pinned to PKIX validation (DANE assists)
//	2  DANE-TA — cert anchored at a DANE-published CA (PKIX bypass)
//	3  DANE-EE — leaf pinned directly (PKIX bypass)
//
// Only usage 2 and 3 are RFC 7672-compliant for SMTP (operators MUST
// use DANE-TA or DANE-EE per §3.1.3). Records with usage 0/1 are
// flagged informationally — they don't confer the PKIX-bypass benefit
// RFC 7672 intends.

// mxDANEResult is the per-MX DANE TLSA verdict.
type mxDANEResult struct {
	MXHost          string `json:"mx_host"`
	Found           bool   `json:"found"`
	RecordCount     int    `json:"record_count,omitempty"`
	HasDANEEE       bool   `json:"has_dane_ee,omitempty"`   // usage=3 (DANE-EE)
	HasDANETA       bool   `json:"has_dane_ta,omitempty"`   // usage=2 (DANE-TA)
	HasPKIX         bool   `json:"has_pkix,omitempty"`      // usage=0 or 1 (advisory only per RFC 7672)
	SMTPCompliant   bool   `json:"smtp_compliant"`          // ≥1 record with usage 2 or 3
	Note            string `json:"note,omitempty"`
}

// probeMXDANE runs a TLSA lookup at _25._tcp.<mxhost> for every MX
// in the supplied list and returns the per-MX verdict.
func probeMXDANE(mxHosts []string, transport *dnsTransport, timeout time.Duration) []mxDANEResult {
	out := make([]mxDANEResult, 0, len(mxHosts))
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}
	for _, mxHost := range mxHosts {
		host := strings.TrimSuffix(mxHost, ".")
		fqdn := "_25._tcp." + dns.Fqdn(host)
		rrs, err := queryDNS(fqdn, dns.TypeTLSA, transport, perProbe)
		r := mxDANEResult{MXHost: host}
		if err != nil || len(rrs) == 0 {
			r.Note = "no TLSA record at _25._tcp"
			out = append(out, r)
			continue
		}
		for _, rr := range rrs {
			tlsa, ok := rr.(*dns.TLSA)
			if !ok {
				continue
			}
			r.Found = true
			r.RecordCount++
			switch tlsa.Usage {
			case 0:
				r.HasPKIX = true
			case 1:
				r.HasPKIX = true
			case 2:
				r.HasDANETA = true
				r.SMTPCompliant = true
			case 3:
				r.HasDANEEE = true
				r.SMTPCompliant = true
			}
		}
		if !r.SMTPCompliant && r.HasPKIX {
			r.Note = "TLSA present but usage 0/1 (PKIX) — RFC 7672 §3.1.3 requires 2 (DANE-TA) or 3 (DANE-EE) for SMTP"
		}
		out = append(out, r)
	}
	return out
}

// mxDANEHeadline returns a one-line summary for the Mail check's hint.
func mxDANEHeadline(results []mxDANEResult) string {
	if len(results) == 0 {
		return ""
	}
	compliant := 0
	hasAny := 0
	for _, r := range results {
		if r.Found {
			hasAny++
		}
		if r.SMTPCompliant {
			compliant++
		}
	}
	if hasAny == 0 {
		return "DANE-MX: none"
	}
	if compliant == len(results) {
		return "DANE-MX ✓ all"
	}
	return "DANE-MX " + strconv.Itoa(compliant) + "/" + strconv.Itoa(len(results))
}
