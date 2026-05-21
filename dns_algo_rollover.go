package main

import (
	"github.com/miekg/dns"
)

// DNSSEC algorithm-rollover detection. A zone is mid-rollover when its
// DNSKEY RRset contains DS-mapped algorithms from two distinct families
// simultaneously (e.g. RSASHA256 + ECDSAP256SHA256), indicating the zone
// is transitioning. Operators do this intentionally — but mid-rollover
// posture is a temporary window where misconfiguration risk is highest.
//
// netdoc surfaces:
//   - Number of DNSKEY algorithms in use
//   - Whether algorithms span families (e.g. RSA + ECDSA + EdDSA)
//   - "rollover in progress" verdict when ≥2 algorithm families coexist
//
// References:
//   RFC 6781 §4 (Algorithm Rollover)
//   RFC 7583 (Timing of DNSSEC Key Rollover)
//   RFC 8624 (Algorithm Implementation Requirements)

// rolloverResult records the verdict.
type rolloverResult struct {
	Analyzed     bool     `json:"analyzed"`
	Algorithms   []uint8  `json:"algorithms,omitempty"`   // distinct DNSKEY algs observed
	AlgorithmsNamed []string `json:"algorithms_named,omitempty"` // human labels
	Families     []string `json:"families,omitempty"`     // "RSA" / "ECDSA" / "EdDSA" / etc.
	InProgress   bool     `json:"in_progress,omitempty"`  // multiple families coexist
}

// analyzeDNSSECRollover walks a DNSSEC chain and surfaces algorithm-family
// transitions across levels. We piggyback on chain data already collected
// so this adds no extra DNS queries.
func analyzeDNSSECRollover(chain *dnssecValidation) rolloverResult {
	out := rolloverResult{Analyzed: true}
	if chain == nil || len(chain.Levels) == 0 {
		out.Analyzed = false
		return out
	}
	// Walk all levels to detect family transitions across the chain.
	families := make(map[string]bool)
	algs := make(map[string]bool)
	for _, lv := range chain.Levels {
		if lv.Algorithm == "" {
			continue
		}
		if !algs[lv.Algorithm] {
			algs[lv.Algorithm] = true
			out.AlgorithmsNamed = append(out.AlgorithmsNamed, lv.Algorithm)
		}
		fam := algorithmFamily(lv.Algorithm)
		if fam != "" && !families[fam] {
			families[fam] = true
			out.Families = append(out.Families, fam)
		}
	}
	out.InProgress = len(out.Families) >= 2
	return out
}

// analyzeDNSKEYRollover takes the raw DNSKEY RRset for a zone and reports
// rollover-detection from algorithm diversity. This is the proper-input
// variant — caller queries DNSKEY explicitly and passes the records.
func analyzeDNSKEYRollover(dnskeys []dns.RR) rolloverResult {
	out := rolloverResult{Analyzed: true}
	seen := make(map[uint8]bool)
	families := make(map[string]bool)
	for _, rr := range dnskeys {
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		if seen[dk.Algorithm] {
			continue
		}
		seen[dk.Algorithm] = true
		out.Algorithms = append(out.Algorithms, dk.Algorithm)
		named := dnssecAlgorithmName(dk.Algorithm)
		out.AlgorithmsNamed = append(out.AlgorithmsNamed, named)
		fam := algorithmFamily(named)
		if !families[fam] && fam != "" {
			families[fam] = true
			out.Families = append(out.Families, fam)
		}
	}
	out.InProgress = len(out.Families) >= 2
	return out
}

// algorithmFamily groups DNSKEY algorithm names by cryptographic family.
func algorithmFamily(name string) string {
	switch name {
	case "RSAMD5", "DSA", "RSASHA1", "DSA-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1",
		"RSASHA256", "RSASHA512":
		return "RSA"
	case "ECC-GOST":
		return "GOST"
	case "ECDSAP256SHA256", "ECDSAP384SHA384":
		return "ECDSA"
	case "ED25519", "ED448":
		return "EdDSA"
	}
	return ""
}

// dnssecAlgorithmName maps DNSKEY algorithm codes (RFC 8624 §3.1) to
// human-readable names.
func dnssecAlgorithmName(code uint8) string {
	switch code {
	case 1:
		return "RSAMD5"
	case 3:
		return "DSA"
	case 5:
		return "RSASHA1"
	case 6:
		return "DSA-NSEC3-SHA1"
	case 7:
		return "RSASHA1-NSEC3-SHA1"
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 12:
		return "ECC-GOST"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	case 16:
		return "ED448"
	}
	return ""
}

// rolloverHeadline returns "rollover: RSA→ECDSA" when in progress.
func rolloverHeadline(r rolloverResult) string {
	if !r.Analyzed || !r.InProgress {
		return ""
	}
	out := "rollover: "
	for i, f := range r.Families {
		if i > 0 {
			out += "+"
		}
		out += f
	}
	return out
}
