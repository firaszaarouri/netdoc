package main

import (
	"time"

	"github.com/miekg/dns"
)

// dnssecStatus describes a domain's DNSSEC posture across three escalating
// confidence levels:
//
//   - Signed: the zone serves RRSIG records over the answer.
//   - Validated: the upstream resolver's AD bit was set (we trust the resolver).
//   - ChainValidated: netdoc walked from the IANA root anchor down to the zone
//     and self-verified every DS / DNSKEY / RRSIG. This is the strong claim;
//     anything less is reported with a weaker label.
type dnssecStatus struct {
	Signed         bool              `json:"signed"`
	Validated      bool              `json:"validated"`
	ChainValidated bool              `json:"chain_validated"`
	Algorithm      string            `json:"algorithm,omitempty"`
	Chain          *dnssecValidation `json:"chain,omitempty"`
}

// checkDNSSECStatus issues an A query with the EDNS DO bit set, then — if
// the zone serves RRSIGs — walks the trust chain from the IANA root anchor
// down to the queried name, self-verifying every signature.
func checkDNSSECStatus(host string, transport *dnsTransport, timeout time.Duration) dnssecStatus {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // 4096-byte UDP buffer, DO bit on

	r, err := dnsExchange(m, transport, timeout)
	if err != nil || r == nil {
		return dnssecStatus{}
	}

	status := dnssecStatus{Validated: r.AuthenticatedData}
	for _, rr := range r.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			status.Signed = true
			if name, found := dns.AlgorithmToString[sig.Algorithm]; found {
				status.Algorithm = name
			}
			break
		}
	}
	if status.Signed {
		// Self-validate the chain from the root trust anchor. Best-effort:
		// failures leave ChainValidated = false but never block the report.
		chain := validateDNSSECChain(host, transport, timeout)
		status.Chain = chain
		status.ChainValidated = chain.Validated
	}
	return status
}
