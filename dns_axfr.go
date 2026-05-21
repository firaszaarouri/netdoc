package main

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// AXFR (zone transfer) probe. Attempts a full zone transfer against every
// authoritative NS. Modern servers REFUSE/NOTAUTH AXFR from arbitrary
// clients — that's the expected, hardened posture. Any NS that ACTUALLY
// transfers the zone is a serious info-leak finding (full zone contents).
//
// dig/kdig/q all support AXFR with -t AXFR; netdoc does the full-NS-list
// fan-out + posture verdict automatically.

// axfrResult is one NS's response to our AXFR request.
type axfrResult struct {
	NS         string `json:"ns"`
	Refused    bool   `json:"refused"`            // got REFUSED/NOTAUTH/SERVFAIL — expected, hardened
	Transferred bool  `json:"transferred"`        // got actual SOA + RRs — VULNERABLE
	RecordCount int   `json:"record_count,omitempty"`
	Error      string `json:"error,omitempty"`
}

// probeAXFRAll attempts AXFR against the supplied NS list in parallel.
// Returns one result per NS. Empty input returns nil.
func probeAXFRAll(zone string, nameservers []string, timeout time.Duration) []axfrResult {
	if len(nameservers) == 0 {
		return nil
	}
	if len(nameservers) > 8 {
		nameservers = nameservers[:8]
	}
	if timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	results := make([]axfrResult, len(nameservers))
	var wg sync.WaitGroup
	for i, ns := range nameservers {
		wg.Add(1)
		go func(idx int, nsHost string) {
			defer wg.Done()
			results[idx] = probeAXFR(zone, nsHost, timeout)
		}(i, ns)
	}
	wg.Wait()
	return results
}

func probeAXFR(zone, nsHost string, timeout time.Duration) axfrResult {
	r := axfrResult{NS: nsHost}
	addr := nsHost
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	tr := &dns.Transfer{}
	tr.DialTimeout = timeout
	tr.ReadTimeout = timeout
	tr.WriteTimeout = timeout

	msg := &dns.Msg{}
	msg.SetAxfr(dns.Fqdn(zone))

	envCh, err := tr.In(msg, addr)
	if err != nil {
		r.Error = tidyErr(err)
		// Most refusal modes manifest as a TCP-level reset or a SERVFAIL/
		// REFUSED inside the first envelope. The server-side soft NO is
		// the *desired* outcome — treat dial-time and read-time errors
		// equivalently as "refused".
		r.Refused = true
		return r
	}
	for env := range envCh {
		if env.Error != nil {
			r.Error = tidyErr(env.Error)
			r.Refused = true
			break
		}
		r.RecordCount += len(env.RR)
		// Cap at 10000 so a hostile-large zone doesn't blow our memory.
		if r.RecordCount > 10000 {
			break
		}
	}
	if r.RecordCount > 0 {
		r.Transferred = true
		r.Refused = false
	}
	return r
}

// axfrHeadline returns "AXFR refused (8/8 NS)" / "AXFR ALLOWED on N NS"
// for the second hint line. The dangerous case gets shouted; the safe
// case is silent (no clutter when the posture is right).
func axfrHeadline(results []axfrResult) string {
	if len(results) == 0 {
		return ""
	}
	open := 0
	for _, r := range results {
		if r.Transferred {
			open++
		}
	}
	if open == 0 {
		return "" // healthy — don't crowd the line
	}
	return "AXFR OPEN on " + itoa(open) + " NS — zone exposed!"
}
