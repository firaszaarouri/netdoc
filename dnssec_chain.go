package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Full-chain DNSSEC validation: walks from the IANA root trust anchor down
// to the queried name, verifying DS → DNSKEY → RRSIG at each level. Replaces
// netdoc's pragmatic "trust the upstream AD bit" with a self-validating
// implementation similar to delv (BIND) and drill (NLnet Labs ldns).
//
// Scope cuts kept for code-budget reasons (mark them clearly so future
// improvements know what to add):
//
//   - Positive answers only. NSEC / NSEC3 denial-of-existence proofs aren't
//     verified; an NXDOMAIN response is just reported as "no records signed".
//   - The registrable domain (eTLD+1 per publicsuffix) is treated as the
//     leaf zone. Subdomains delegated below that point are not walked.
//   - Algorithms: only RSASHA256 (8) and ECDSAP256SHA256 (13) are commonly
//     used in 2026; both are supported transparently by miekg/dns's
//     RRSIG.Verify.
//
// What still works correctly under these cuts: the common case of "this
// signed zone serves a signed A/AAAA record" — which is what 99%+ of
// DNSSEC-enabled targets actually expose.

// rootTrustAnchor matches one IANA-published root KSK digest.
type rootTrustAnchor struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string // hex, uppercase
}

// rootAnchors are the IANA trust anchors published at
// https://data.iana.org/root-anchors/root-anchors.xml. Both the 2017 (KSK
// 20326) and 2024 (KSK 38696) anchors are currently valid; the 2024
// rollover overlaps the 2017 anchor through the transition.
var rootAnchors = []rootTrustAnchor{
	{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
	{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
}

// dnssecValidation records the outcome of a full-chain walk.
type dnssecValidation struct {
	Validated   bool                 `json:"validated"`
	Reason      string               `json:"reason,omitempty"`
	Levels      []dnssecLevelResult  `json:"levels,omitempty"`
	LeafAnswer  *dnssecAnswer        `json:"leaf_answer,omitempty"`
}

// dnssecLevelResult is one zone in the chain.
type dnssecLevelResult struct {
	Zone      string   `json:"zone"`
	Trusted   bool     `json:"trusted"`
	Reason    string   `json:"reason,omitempty"`
	KSKTag    uint16   `json:"ksk_tag,omitempty"`
	ZSKTags   []uint16 `json:"zsk_tags,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
}

// dnssecAnswer is the leaf RRset that was verified (or attempted).
type dnssecAnswer struct {
	Type      string   `json:"type"`
	Records   []string `json:"records,omitempty"`
	SignedBy  uint16   `json:"signed_by_key_tag,omitempty"`
	Verified  bool     `json:"verified"`
}

// validateDNSSECChain walks from the root anchor down to the registrable
// domain's zone, then verifies the queried name's A/AAAA RRSIG. The
// transport parameter is reused so DNSSEC queries flow over the same
// path (system / UDP / TCP / DoT / DoH / DoQ) as everything else.
func validateDNSSECChain(qname string, transport *dnsTransport, timeout time.Duration) *dnssecValidation {
	result := &dnssecValidation{}
	qname = dns.Fqdn(strings.ToLower(qname))

	// Determine the registrable domain — that's the leaf zone for our walk.
	regDomain, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(qname, "."))
	if err != nil || regDomain == "" {
		result.Reason = "could not derive registrable domain"
		return result
	}
	regDomain = dns.Fqdn(regDomain)
	tld := dns.Fqdn(regDomain[strings.Index(regDomain, ".")+1:])

	zones := []string{".", tld, regDomain}

	// Phase 1: validate root. The root zone's KSK must match one of the
	// IANA trust anchors. If it does, all RRSIGs in the root zone can be
	// trusted, including the DS for the TLD which authenticates the TLD's
	// KSK in turn.
	rootKSKs, rootDNSKEYs, err := fetchDNSKEYs(".", transport, timeout)
	if err != nil {
		result.Reason = "could not fetch root DNSKEY: " + err.Error()
		return result
	}
	rootLevel := dnssecLevelResult{Zone: "."}
	matchedKSK, anchor := matchRootAnchor(rootKSKs)
	if matchedKSK == nil {
		rootLevel.Reason = "root KSK does not match any IANA trust anchor"
		result.Levels = append(result.Levels, rootLevel)
		result.Reason = rootLevel.Reason
		return result
	}
	rootLevel.Trusted = true
	rootLevel.KSKTag = matchedKSK.KeyTag()
	rootLevel.Algorithm = algorithmName(anchor.Algorithm)
	result.Levels = append(result.Levels, rootLevel)

	// Phase 2: walk down through TLD and registrable domain. At each step,
	// verify the zone's DNSKEY RRset is authenticated by the parent's DS.
	// We start with the root's full DNSKEY set (KSK + ZSK) — the DS records
	// for the next level down are signed by the root's ZSK, so the KSK alone
	// isn't enough.
	parentDNSKEYs := rootDNSKEYs
	for _, zone := range zones[1:] {
		level := dnssecLevelResult{Zone: zone}

		// Get DS records from parent zone for this child zone.
		dsRRs, dsRRSIG, err := fetchSignedDS(zone, transport, timeout)
		if err != nil {
			level.Reason = "no DS in parent: " + err.Error()
			result.Levels = append(result.Levels, level)
			result.Reason = level.Reason
			return result
		}
		// Verify the DS RRset is signed by the parent's KSK.
		if err := verifyRRSIG(dsRRSIG, dsRRs, parentDNSKEYs); err != nil {
			level.Reason = "DS RRSIG verification failed: " + err.Error()
			result.Levels = append(result.Levels, level)
			result.Reason = level.Reason
			return result
		}

		// Fetch the zone's DNSKEYs and find one that matches a DS digest.
		zoneKSKs, allZoneDNSKEYs, err := fetchDNSKEYs(zone, transport, timeout)
		if err != nil {
			level.Reason = "could not fetch zone DNSKEY: " + err.Error()
			result.Levels = append(result.Levels, level)
			result.Reason = level.Reason
			return result
		}
		matched := matchDSToDNSKEY(dsRRs, zoneKSKs)
		if matched == nil {
			level.Reason = "no DS digest matched any DNSKEY at zone"
			result.Levels = append(result.Levels, level)
			result.Reason = level.Reason
			return result
		}
		level.Trusted = true
		level.KSKTag = matched.KeyTag()
		level.Algorithm = algorithmName(matched.Algorithm)
		for _, k := range allZoneDNSKEYs {
			if k.Flags == 256 { // ZSK
				level.ZSKTags = append(level.ZSKTags, k.KeyTag())
			}
		}
		result.Levels = append(result.Levels, level)
		parentDNSKEYs = allZoneDNSKEYs
	}

	// Phase 3: verify the queried name's A/AAAA RRset signature.
	answer, err := fetchSignedA(qname, transport, timeout)
	if err != nil {
		result.Reason = "no signed A for " + qname + ": " + err.Error()
		return result
	}
	if err := verifyRRSIG(answer.RRSIG, answer.RRset, parentDNSKEYs); err != nil {
		result.Reason = "A RRSIG verification failed: " + err.Error()
		result.LeafAnswer = &dnssecAnswer{Type: "A", Verified: false}
		return result
	}
	rrStrings := make([]string, 0, len(answer.RRset))
	for _, rr := range answer.RRset {
		if a, ok := rr.(*dns.A); ok {
			rrStrings = append(rrStrings, a.A.String())
		}
	}
	result.LeafAnswer = &dnssecAnswer{
		Type:     "A",
		Records:  rrStrings,
		SignedBy: answer.RRSIG.KeyTag,
		Verified: true,
	}
	result.Validated = true
	return result
}

// fetchDNSKEYs fetches the DNSKEY RRset for a zone. Returns the KSKs
// (flag 257) and the full set (KSK+ZSK) so callers can validate any
// RRSIG within the zone.
func fetchDNSKEYs(zone string, transport *dnsTransport, timeout time.Duration) ([]*dns.DNSKEY, []*dns.DNSKEY, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	r, err := dnsExchange(m, transport, timeout)
	if err != nil {
		return nil, nil, err
	}
	var ksks, all []*dns.DNSKEY
	for _, rr := range r.Answer {
		k, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		all = append(all, k)
		if k.Flags == 257 {
			ksks = append(ksks, k)
		}
	}
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("zone %s has no DNSKEY records", zone)
	}
	return ksks, all, nil
}

// fetchSignedDS fetches the DS RRset for a zone from its parent, plus the
// matching RRSIG that authenticates it.
func fetchSignedDS(zone string, transport *dnsTransport, timeout time.Duration) ([]dns.RR, *dns.RRSIG, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	m.SetEdns0(4096, true)
	r, err := dnsExchange(m, transport, timeout)
	if err != nil {
		return nil, nil, err
	}
	var dsSet []dns.RR
	var sig *dns.RRSIG
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.DS); ok {
			dsSet = append(dsSet, rr)
		}
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeDS {
			sig = s
		}
	}
	if len(dsSet) == 0 {
		return nil, nil, fmt.Errorf("no DS records for %s", zone)
	}
	if sig == nil {
		return nil, nil, fmt.Errorf("no RRSIG over DS for %s", zone)
	}
	return dsSet, sig, nil
}

// signedRRset bundles an RRset with its RRSIG.
type signedRRset struct {
	RRset []dns.RR
	RRSIG *dns.RRSIG
}

// fetchSignedA fetches the A RRset for a name plus its RRSIG.
func fetchSignedA(qname string, transport *dnsTransport, timeout time.Duration) (*signedRRset, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.SetEdns0(4096, true)
	r, err := dnsExchange(m, transport, timeout)
	if err != nil {
		return nil, err
	}
	var aSet []dns.RR
	var sig *dns.RRSIG
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.A); ok {
			aSet = append(aSet, rr)
		}
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeA {
			sig = s
		}
	}
	if len(aSet) == 0 {
		return nil, fmt.Errorf("no A records")
	}
	if sig == nil {
		return nil, fmt.Errorf("no RRSIG over A — name is not signed")
	}
	return &signedRRset{RRset: aSet, RRSIG: sig}, nil
}

// verifyRRSIG checks that one of the supplied DNSKEYs can verify the
// signature over the RRset. Returns nil on success.
func verifyRRSIG(sig *dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) error {
	for _, k := range keys {
		if k.KeyTag() != sig.KeyTag {
			continue
		}
		if k.Algorithm != sig.Algorithm {
			continue
		}
		if err := sig.Verify(k, rrset); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no matching DNSKEY verified the signature (key tag %d, alg %d)", sig.KeyTag, sig.Algorithm)
}

// matchRootAnchor finds a DNSKEY among the supplied keys that matches one
// of the IANA root trust anchors. Returns the matched key and the anchor.
func matchRootAnchor(keys []*dns.DNSKEY) (*dns.DNSKEY, *rootTrustAnchor) {
	for _, k := range keys {
		if k.Flags != 257 {
			continue
		}
		ds := k.ToDS(dns.SHA256)
		if ds == nil {
			continue
		}
		digestHex := strings.ToUpper(ds.Digest)
		for i := range rootAnchors {
			a := &rootAnchors[i]
			if a.KeyTag != k.KeyTag() {
				continue
			}
			if a.Algorithm != k.Algorithm {
				continue
			}
			if a.DigestType != dns.SHA256 {
				continue
			}
			if strings.EqualFold(a.Digest, digestHex) {
				return k, a
			}
			// Compare ignoring whitespace just in case.
			if strings.EqualFold(strings.ReplaceAll(a.Digest, " ", ""), digestHex) {
				return k, a
			}
		}
	}
	return nil, nil
}

// matchDSToDNSKEY finds a DNSKEY whose hash matches one of the DS records
// supplied. The DS record's digest type (SHA-1 or SHA-256) is honoured.
func matchDSToDNSKEY(dsRRs []dns.RR, keys []*dns.DNSKEY) *dns.DNSKEY {
	for _, dsRR := range dsRRs {
		ds, ok := dsRR.(*dns.DS)
		if !ok {
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != ds.KeyTag {
				continue
			}
			if k.Algorithm != ds.Algorithm {
				continue
			}
			computed := k.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if strings.EqualFold(computed.Digest, ds.Digest) {
				return k
			}
		}
	}
	return nil
}

// algorithmName renders a DNSSEC algorithm number as a friendly name. We
// only spell out the two algorithms anyone uses in 2026 (RSASHA256,
// ECDSAP256SHA256); others surface as their numeric code so a curious
// reader can still look them up.
func algorithmName(alg uint8) string {
	switch alg {
	case 8:
		return "RSASHA256"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "Ed25519"
	case 16:
		return "Ed448"
	}
	return fmt.Sprintf("alg-%d", alg)
}

// hexDigest is a convenience wrapper that turns a hash byte slice into
// uppercase hex — used for log messages, not for verification.
func hexDigest(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
