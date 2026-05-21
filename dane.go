package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DANE — DNS-based Authentication of Named Entities (RFC 6698). TLSA
// records published at well-known DNS labels pin a server's cert (or its
// SPKI) to a hash. The binding is meaningful only when DNSSEC validates the
// TLSA record, since otherwise a network attacker can substitute one.
//
// Probe surfaces:
//   - whether TLSA records exist at _<port>._tcp.<host>
//   - whether any record matches the cert chain the server presented
//   - the (Usage / Selector / MatchingType) tuple in human terms
//
// Hardenize and internet.nl both report TLSA pairing as a top-line signal
// for both web (port 443) and mail (port 25 of every MX).

// tlsaRecord is one parsed TLSA record + match verdict.
type tlsaRecord struct {
	Usage         uint8  `json:"usage"`          // 0 CA, 1 SC, 2 TA, 3 DI
	Selector      uint8  `json:"selector"`       // 0 full cert, 1 SPKI
	MatchingType  uint8  `json:"matching_type"`  // 0 exact, 1 sha-256, 2 sha-512
	Cert          string `json:"cert"`           // hex of association data
	UsageStr      string `json:"usage_str"`
	SelectorStr   string `json:"selector_str"`
	MatchingStr   string `json:"matching_str"`
	Matched       bool   `json:"matched"`
}

// daneResult collects the per-host TLSA verdict.
type daneResult struct {
	QueryName       string       `json:"query_name"`
	Records         []tlsaRecord `json:"records,omitempty"`
	AnyMatched      bool         `json:"any_matched"`
	DNSSECRequired  bool         `json:"dnssec_required"` // true → user should also check dnssec.chain_validated
	Issues          []string     `json:"issues,omitempty"`
}

// probeDANE looks up TLSA records at _<port>._tcp.<host> and checks them
// against the supplied cert chain. Returns nil when no TLSA records exist.
func probeDANE(host string, port int, leaf *x509.Certificate, chain []*x509.Certificate, transport *dnsTransport, timeout time.Duration) *daneResult {
	qname := fmt.Sprintf("_%d._tcp.%s", port, strings.TrimSuffix(host, "."))
	rrs, err := queryDNS(qname, dns.TypeTLSA, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return nil
	}
	res := &daneResult{
		QueryName:      qname,
		DNSSECRequired: true,
	}
	for _, rr := range rrs {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		entry := tlsaRecord{
			Usage:        t.Usage,
			Selector:     t.Selector,
			MatchingType: t.MatchingType,
			Cert:         strings.ToLower(t.Certificate),
			UsageStr:     tlsaUsageName(t.Usage),
			SelectorStr:  tlsaSelectorName(t.Selector),
			MatchingStr:  tlsaMatchingName(t.MatchingType),
		}
		entry.Matched = tlsaMatchesChain(t, leaf, chain)
		if entry.Matched {
			res.AnyMatched = true
		}
		res.Records = append(res.Records, entry)
	}
	if !res.AnyMatched {
		res.Issues = append(res.Issues, "TLSA published but no record matches the presented cert")
	}
	return res
}

// tlsaMatchesChain checks whether the TLSA record's association data
// matches any cert in the supplied chain (per Usage). Implements the
// common Usage values (1, 3 = direct cert hash; 0, 2 = chain anchor).
func tlsaMatchesChain(t *dns.TLSA, leaf *x509.Certificate, chain []*x509.Certificate) bool {
	candidates := []*x509.Certificate{leaf}
	if t.Usage == 0 || t.Usage == 2 {
		candidates = chain // CA / trust-anchor — match anywhere in chain
	}
	for _, c := range candidates {
		var data []byte
		switch t.Selector {
		case 0:
			data = c.Raw
		case 1:
			data = c.RawSubjectPublicKeyInfo
		default:
			continue
		}
		var matchHex string
		switch t.MatchingType {
		case 0:
			matchHex = strings.ToLower(hex.EncodeToString(data))
		case 1:
			sum := sha256.Sum256(data)
			matchHex = strings.ToLower(hex.EncodeToString(sum[:]))
		case 2:
			sum := sha512.Sum512(data)
			matchHex = strings.ToLower(hex.EncodeToString(sum[:]))
		default:
			continue
		}
		if matchHex == strings.ToLower(t.Certificate) {
			return true
		}
	}
	return false
}

func tlsaUsageName(u uint8) string {
	switch u {
	case 0:
		return "PKIX-TA (CA constraint)"
	case 1:
		return "PKIX-EE (service-cert constraint)"
	case 2:
		return "DANE-TA (trust-anchor assertion)"
	case 3:
		return "DANE-EE (domain-issued cert)"
	}
	return fmt.Sprintf("Usage %d", u)
}

func tlsaSelectorName(s uint8) string {
	switch s {
	case 0:
		return "full cert"
	case 1:
		return "SPKI"
	}
	return fmt.Sprintf("Selector %d", s)
}

func tlsaMatchingName(m uint8) string {
	switch m {
	case 0:
		return "exact"
	case 1:
		return "SHA-256"
	case 2:
		return "SHA-512"
	}
	return fmt.Sprintf("MatchingType %d", m)
}
