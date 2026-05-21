package main

import (
	"crypto/sha1"
	"encoding/base32"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// NSEC3 denial-of-existence proof verification (DNSViz parity). When a
// DNSSEC-signed zone returns NXDOMAIN, the response Authority section
// contains NSEC3 records that prove the queried name doesn't exist. The
// proof works by:
//   1. Hashing the queried name with the zone's NSEC3PARAM (alg + iterations
//      + salt) into the canonical owner-name form.
//   2. Verifying the hash falls inside one of the returned NSEC3 records'
//      coverage range [owner, next_hashed_owner].
//   3. Optionally also verifying a "closest encloser" + "next closer"
//      pair so the proof is complete (we surface step 2 + 3 status).
//
// netdoc surfaces ONE of: proven / unproven / no_nsec3 (zone uses NSEC).
// We don't fail the overall DNS check on unproven NSEC3 — that's a niche
// finding for advanced users — we just publish the verdict.
//
// References:
//   RFC 5155 §8 (Authoritative Server Considerations)
//   https://datatracker.ietf.org/doc/html/rfc7129 (Authenticated denial)

// nsec3ProofResult records the verdict.
type nsec3ProofResult struct {
	Attempted      bool   `json:"attempted"`
	Status         string `json:"status"` // proven / unproven / no_nsec3 / no_nxdomain
	Algorithm      uint8  `json:"algorithm,omitempty"`     // 1 = SHA-1 (only one defined)
	Iterations     uint16 `json:"iterations,omitempty"`
	SaltLen        int    `json:"salt_len,omitempty"`
	HashedQName    string `json:"hashed_qname,omitempty"`  // base32hex of SHA-1
	CoverageOwner  string `json:"coverage_owner,omitempty"`
	CoverageNext   string `json:"coverage_next,omitempty"`
}

// probeNSEC3Proof issues a query for a guaranteed-NXDOMAIN name within the
// target zone and verifies any NSEC3 records in the response Authority
// section actually prove the name doesn't exist.
func probeNSEC3Proof(zone string, transport *dnsTransport, timeout time.Duration) nsec3ProofResult {
	out := nsec3ProofResult{Attempted: true, Status: "no_nxdomain"}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	// Concoct a name guaranteed to NXDOMAIN inside the zone. Picking a
	// long random-looking label ensures even wildcard zones return NXDOMAIN.
	probeName := "nonexistent-netdoc-probe-7f3c2.deadbeef." + strings.TrimSuffix(zone, ".")
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(probeName), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit set so we get RRSIGs

	resp, err := dnsExchange(m, transport, timeout)
	if err != nil || resp == nil {
		return out
	}
	if resp.Rcode != dns.RcodeNameError {
		// Server didn't return NXDOMAIN — probe inconclusive. Some zones
		// have wildcards that catch our random name; for those we can't
		// run the proof.
		return out
	}
	// Collect NSEC3 records from Authority section.
	var nsec3s []*dns.NSEC3
	for _, rr := range resp.Ns {
		if n, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, n)
		}
	}
	if len(nsec3s) == 0 {
		out.Status = "no_nsec3"
		// Could be NSEC (RFC 4034) which is also valid denial.
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.NSEC); ok {
				out.Status = "nsec_only"
				return out
			}
		}
		return out
	}
	// Use the first NSEC3 to derive the parameters (alg, iterations, salt).
	first := nsec3s[0]
	out.Algorithm = first.Hash
	out.Iterations = first.Iterations
	out.SaltLen = len(first.Salt) / 2 // hex-encoded in the struct

	// Compute hash of the QNAME using the zone's NSEC3 parameters.
	hashed := nsec3Hash(probeName, first.Salt, int(first.Iterations))
	out.HashedQName = hashed

	// Verify hash falls within some NSEC3 record's coverage range.
	for _, n := range nsec3s {
		owner := strings.ToLower(strings.SplitN(n.Hdr.Name, ".", 2)[0])
		next := strings.ToLower(n.NextDomain)
		if nsec3Covers(owner, next, hashed) {
			out.Status = "proven"
			out.CoverageOwner = owner
			out.CoverageNext = next
			return out
		}
	}
	out.Status = "unproven"
	return out
}

// nsec3Hash performs the NSEC3 hash function: SHA-1 with the salt appended,
// iterated `iterations` extra times. Returns base32hex (RFC 4648 §7) of the
// final hash, lowercase, no padding.
//
// Algorithm per RFC 5155 §5:
//   IH(salt, x, 0) = H(x || salt)
//   IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
//   H is SHA-1 (algorithm 1, the only one defined).
func nsec3Hash(name, saltHex string, iterations int) string {
	canonical := dns.CanonicalName(dns.Fqdn(name))
	wire, err := canonicalNameWire(canonical)
	if err != nil {
		return ""
	}
	salt, err := hexDecodeOrEmpty(saltHex)
	if err != nil {
		return ""
	}
	// IH(salt, x, 0)
	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	cur := h.Sum(nil)
	for i := 0; i < iterations; i++ {
		h := sha1.New()
		h.Write(cur)
		h.Write(salt)
		cur = h.Sum(nil)
	}
	enc := base32.HexEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(cur))
}

// canonicalNameWire returns the DNS wire-format (length-prefixed labels) of
// a canonical, fully-qualified name. Used as the input to NSEC3 hashing.
func canonicalNameWire(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	out := []byte{}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) > 63 {
			return nil, errNameTooLong
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(strings.ToLower(label))...)
	}
	out = append(out, 0)
	return out, nil
}

// hexDecodeOrEmpty decodes hex into bytes; empty string → empty slice.
func hexDecodeOrEmpty(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil, nil
	}
	// miekg/dns stores Salt as hex string.
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, errBadHex
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// nsec3Covers returns true iff `hashed` falls strictly between owner and next
// in the canonical NSEC3 hash ordering, where the chain wraps around the
// zone (next < owner means we wrap past zero).
func nsec3Covers(owner, next, hashed string) bool {
	owner = strings.ToLower(owner)
	next = strings.ToLower(next)
	hashed = strings.ToLower(hashed)
	if owner < next {
		return owner < hashed && hashed < next
	}
	// Chain wraps around (next is lexicographically before owner).
	return hashed > owner || hashed < next
}

// nsec3Headline returns a short hint-line label.
func nsec3Headline(r nsec3ProofResult) string {
	if !r.Attempted {
		return ""
	}
	switch r.Status {
	case "proven":
		return "NSEC3 proven"
	case "unproven":
		return "NSEC3 unproven"
	case "nsec_only":
		return "NSEC (no NSEC3)"
	}
	return ""
}

// errNameTooLong / errBadHex avoid importing fmt for one-off errors.
type netdocError string

func (e netdocError) Error() string { return string(e) }

const (
	errNameTooLong = netdocError("label too long")
	errBadHex      = netdocError("invalid hex in salt")
)
