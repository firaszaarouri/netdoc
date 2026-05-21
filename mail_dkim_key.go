package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DKIM key strength validation. Parses each selector's TXT record,
// base64-decodes the `p=` SubjectPublicKeyInfo, extracts the algorithm
// (RSA / Ed25519 / ECDSA) and bit length. Short RSA keys (<1024 bits)
// are considered broken per 2024 NIST DKIM-key-strength guidance.

// dkimKeyInfo describes the public key advertised by one selector.
type dkimKeyInfo struct {
	Selector string `json:"selector"`
	Algo     string `json:"algo,omitempty"` // "rsa", "ed25519", "ecdsa", "unknown"
	Bits     int    `json:"bits,omitempty"` // RSA modulus bits, ECDSA curve bits
	Strong   bool   `json:"strong"`         // meets the 2024 strength baseline
	Reason   string `json:"reason,omitempty"`
}

// parseDKIMKey extracts the algorithm and bit count from a DKIM TXT record.
// Format: "v=DKIM1; k=<algo>; p=<base64 SPKI>" (per RFC 6376 §3.6).
// Returns (info, true) on a successful parse; (info, false) if the record
// can't be parsed (revoked selector marked p=, malformed key, etc).
func parseDKIMKey(selector, txt string) (dkimKeyInfo, bool) {
	info := dkimKeyInfo{Selector: selector}
	tags := parseDKIMTags(txt)

	// Empty p= means the selector was revoked per RFC 6376 §3.6.1.
	pVal := tags["p"]
	if pVal == "" {
		info.Reason = "revoked (p= empty)"
		return info, false
	}

	// Decode the SPKI.
	pVal = strings.ReplaceAll(pVal, " ", "")
	pVal = strings.ReplaceAll(pVal, "\t", "")
	keyBytes, err := base64.StdEncoding.DecodeString(pVal)
	if err != nil {
		// Try URL-safe encoding as fallback.
		keyBytes, err = base64.URLEncoding.DecodeString(pVal)
		if err != nil {
			info.Reason = "base64 decode failed"
			return info, false
		}
	}

	algoTag := strings.ToLower(tags["k"])
	switch algoTag {
	case "", "rsa":
		// Default per RFC 6376 §3.6.1.
		pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			info.Reason = "PKIX parse failed: " + tidyErr(err)
			info.Algo = "rsa"
			return info, false
		}
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			info.Reason = "key tagged k=rsa but not actually RSA"
			info.Algo = "rsa"
			return info, false
		}
		info.Algo = "rsa"
		info.Bits = rsaKey.N.BitLen()
		// 2024 NIST guidance for DKIM-key strength: 2048+ secure, 1024
		// transitional, <1024 broken.
		switch {
		case info.Bits >= 2048:
			info.Strong = true
		case info.Bits >= 1024:
			info.Strong = true // transitional pass
			info.Reason = "1024-bit transitional — recommend 2048+"
		default:
			info.Reason = "RSA key < 1024 bits — broken"
		}
	case "ed25519":
		info.Algo = "ed25519"
		info.Bits = 256
		if len(keyBytes) >= ed25519.PublicKeySize {
			info.Strong = true
		} else {
			info.Reason = "Ed25519 key wrong length"
		}
	case "ecdsa":
		info.Algo = "ecdsa"
		pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			info.Reason = "ECDSA parse failed: " + tidyErr(err)
			return info, false
		}
		ec, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			info.Reason = "key tagged k=ecdsa but not actually ECDSA"
			return info, false
		}
		info.Bits = ec.Curve.Params().BitSize
		if info.Bits >= 256 {
			info.Strong = true
		} else {
			info.Reason = "ECDSA curve < 256 bits"
		}
	default:
		info.Algo = "unknown"
		info.Reason = "unknown k= algorithm: " + algoTag
	}

	return info, info.Strong
}

// parseDKIMTags splits the TXT into tag → value map. Tags are
// "tag=value" separated by ";" per RFC 6376 §3.2.
func parseDKIMTags(txt string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := strings.IndexByte(part, '=')
		if i < 0 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(part[:i]))] = strings.TrimSpace(part[i+1:])
	}
	return out
}

// dkimKeyHeadline summarises the per-selector key-strength findings.
func dkimKeyHeadline(keys []dkimKeyInfo) string {
	if len(keys) == 0 {
		return ""
	}
	strong := 0
	weak := 0
	for _, k := range keys {
		if k.Strong {
			strong++
		} else {
			weak++
		}
	}
	if weak == 0 {
		return "DKIM keys ✓ all strong"
	}
	return "DKIM keys " + strconv.Itoa(strong) + " strong, " + strconv.Itoa(weak) + " weak"
}

// probeDKIMKeyStrength returns the parsed dkimKeyInfo for every found
// selector. Run alongside the existing probeDKIMSelectors which discovers
// which selectors are advertised; this extends each to extract bit-length.
func probeDKIMKeyStrength(domain string, selectors []dkimSelector, transport *dnsTransport, timeout time.Duration) []dkimKeyInfo {
	out := make([]dkimKeyInfo, 0, len(selectors))
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}
	for _, sel := range selectors {
		fqdn := sel.Name + "._domainkey." + domain
		rrs, err := queryDNS(fqdn, dns.TypeTXT, transport, perProbe)
		if err != nil {
			continue
		}
		var txt string
		for _, rr := range rrs {
			if t, ok := rr.(*dns.TXT); ok {
				txt = strings.Join(t.Txt, "")
				break
			}
		}
		if txt == "" {
			continue
		}
		info, _ := parseDKIMKey(sel.Name, txt)
		out = append(out, info)
	}
	return out
}
