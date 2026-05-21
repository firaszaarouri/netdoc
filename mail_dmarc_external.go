package main

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DMARC external destination authorization check (RFC 7489 §7.1). When a
// DMARC `rua=` or `ruf=` URI points to a different organisational domain
// than the DMARC record's own domain, the destination MUST publish a
// special TXT record proving it authorises receiving reports:
//
//   <source-domain>._report._dmarc.<destination-domain> TXT "v=DMARC1"
//
// Without that record, DMARC-compliant report-receivers MUST refuse to
// deliver reports. Most organisations setting `rua=mailto:rep@analytics-vendor.com`
// forget this step — DMARC validators (the receiving MTAs) silently drop
// their reports.
//
// netdoc validates each RUA/RUF endpoint and flags missing authorizations.

// dmarcExternalAuth records the verdict per endpoint.
type dmarcExternalAuth struct {
	URI            string `json:"uri"`
	External       bool   `json:"external"`         // destination differs from source domain
	Destination    string `json:"destination"`      // hostname extracted from URI
	Authorized     bool   `json:"authorized"`       // _report._dmarc TXT found
	ExpectedRecord string `json:"expected_record"`  // human-readable required TXT name
}

// checkDMARCExternalAuth validates every rua/ruf URI in a DMARC policy.
// `source` is the original domain (the one DMARC is FOR); `endpoints` is
// the combined rua + ruf URI list. Returns one result per endpoint.
func checkDMARCExternalAuth(source string, endpoints []string, transport *dnsTransport, timeout time.Duration) []dmarcExternalAuth {
	if len(endpoints) == 0 {
		return nil
	}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	source = strings.ToLower(strings.TrimSuffix(source, "."))
	results := make([]dmarcExternalAuth, len(endpoints))
	var wg sync.WaitGroup
	for i, uri := range endpoints {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			results[idx] = checkOneDMARCAuth(source, u, transport, timeout)
		}(i, uri)
	}
	wg.Wait()
	return results
}

func checkOneDMARCAuth(source, uri string, transport *dnsTransport, timeout time.Duration) dmarcExternalAuth {
	r := dmarcExternalAuth{URI: uri}
	dest := extractDMARCDestination(uri)
	if dest == "" {
		return r
	}
	r.Destination = dest
	// External iff different organisational domain (simplified: different
	// apex). The strict RFC 7489 definition uses the Public Suffix List;
	// we do a label-suffix comparison which catches the common cases.
	r.External = !sameApex(source, dest)
	if !r.External {
		// Same domain → authorization implicit, no check needed.
		r.Authorized = true
		return r
	}
	r.ExpectedRecord = source + "._report._dmarc." + dest
	rrs, err := queryDNS(r.ExpectedRecord, dns.TypeTXT, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return r // not authorized
	}
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			combined := strings.Join(txt.Txt, "")
			if strings.HasPrefix(strings.ToLower(combined), "v=dmarc1") {
				r.Authorized = true
				break
			}
		}
	}
	return r
}

// extractDMARCDestination parses a DMARC URI (mailto: or https:) and
// returns the destination hostname (apex domain).
func extractDMARCDestination(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "mailto:") {
		addr := strings.TrimPrefix(uri, "mailto:")
		addr = strings.TrimPrefix(addr, "MAILTO:")
		// Strip leading optional `!size!` indicator.
		if i := strings.Index(addr, "!"); i >= 0 {
			addr = addr[:i]
		}
		at := strings.LastIndex(addr, "@")
		if at < 0 {
			return ""
		}
		return strings.ToLower(addr[at+1:])
	}
	if u, err := url.Parse(uri); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// sameApex returns true iff two domains share the same apex (e.g.
// example.com and mail.example.com). Uses a 2-label suffix comparison.
func sameApex(a, b string) bool {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))
	if a == b {
		return true
	}
	// Compare the trailing 2 labels.
	la := strings.Split(a, ".")
	lb := strings.Split(b, ".")
	if len(la) < 2 || len(lb) < 2 {
		return false
	}
	return la[len(la)-2] == lb[len(lb)-2] && la[len(la)-1] == lb[len(lb)-1]
}

// dmarcExternalHeadline returns "DMARC reports: 2/3 unauthorized" or empty.
func dmarcExternalHeadline(results []dmarcExternalAuth) string {
	external := 0
	bad := 0
	for _, r := range results {
		if r.External {
			external++
			if !r.Authorized {
				bad++
			}
		}
	}
	if external == 0 || bad == 0 {
		return ""
	}
	return "DMARC reports unauthorized: " + itoa(bad) + "/" + itoa(external) + " external"
}
