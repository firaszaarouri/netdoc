package main

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// --cipher-pattern <pattern> — mirrors testssl.sh's `-x <pattern>` flag.
//
// User specifies a substring or codepoint to match against; we report
// every cipher in our enumeration that matches, along with whether the
// server actually supports it. Useful for compliance / policy work:
//
//   netdoc --cipher-pattern RC4   example.com   # is RC4 anywhere?
//   netdoc --cipher-pattern 3DES  example.com   # is 3DES offered?
//   netdoc --cipher-pattern GCM   example.com   # which GCM suites?
//   netdoc --cipher-pattern 0xc02f example.com  # specific IANA codepoint
//   netdoc --cipher-pattern ChaCha example.com  # any ChaCha20 suite
//
// Pattern matching rules:
//   - Hex prefix (0x or 0X) treated as IANA codepoint match.
//   - Otherwise, case-insensitive substring against the OpenSSL name
//     AND the IANA name (we accept both naming conventions because
//     users come from both worlds).

// cipherPatternMatch reports whether one cipher (by codepoint + name)
// matches the user-supplied pattern.
func cipherPatternMatch(code uint16, name string, pattern string) bool {
	if pattern == "" {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(pattern))
	// Hex codepoint match.
	if strings.HasPrefix(p, "0x") {
		hex := strings.TrimPrefix(p, "0x")
		actual := fmt.Sprintf("%04x", code)
		return actual == hex
	}
	// IANA name (e.g., "TLS_RSA_WITH_AES_128_CBC_SHA") match.
	if strings.Contains(strings.ToLower(name), p) {
		return true
	}
	// OpenSSL name (e.g., "AES128-SHA") match — translate IANA→OpenSSL
	// via tls.CipherSuiteName already gives us the IANA form; OpenSSL
	// names map via opensslName helper.
	if openssl := opensslCipherName(code); openssl != "" {
		if strings.Contains(strings.ToLower(openssl), p) {
			return true
		}
	}
	return false
}

// cipherPatternResult is one row reported when --cipher-pattern is set.
type cipherPatternResult struct {
	Pattern  string                `json:"pattern"`
	Matches  []cipherPatternMatchEntry `json:"matches"`
	HitCount int                   `json:"hit_count"`
}

type cipherPatternMatchEntry struct {
	Code     uint16 `json:"code"`
	Name     string `json:"name"`
	OpenSSL  string `json:"openssl_name,omitempty"`
	Offered  bool   `json:"offered"`
	Grade    string `json:"grade,omitempty"`
	Version  string `json:"tls_version,omitempty"`
}

// filterCiphersByPattern walks the cipher_enum result and returns every
// matching cipher along with whether the server offered it.
func filterCiphersByPattern(enums []cipherEnum, pattern string) cipherPatternResult {
	out := cipherPatternResult{Pattern: pattern}
	seen := make(map[uint16]bool)
	for _, ce := range enums {
		for _, ci := range ce.Ciphers {
			if !cipherPatternMatch(ci.Code, ci.Name, pattern) {
				continue
			}
			if seen[ci.Code] {
				continue
			}
			seen[ci.Code] = true
			out.Matches = append(out.Matches, cipherPatternMatchEntry{
				Code:    ci.Code,
				Name:    ci.Name,
				OpenSSL: opensslCipherName(ci.Code),
				Offered: true,
				Grade:   ci.Grade,
				Version: ce.TLSVersion,
			})
			out.HitCount++
		}
	}
	return out
}

// esIfPlural appends "es" for plurals of words like "match" → "matches".
func esIfPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// opensslCipherName maps a TLS IANA codepoint to its OpenSSL short
// name. The mapping is a curated subset covering ciphers users most
// often type at the CLI — full enumeration would be ~370 entries; this
// covers the high-frequency ones plus all weak/legacy classes so
// policy queries like "RC4" / "3DES" / "EXPORT" find their targets.
func opensslCipherName(code uint16) string {
	switch code {
	// TLS 1.3 suites — OpenSSL uses the IANA name directly.
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	// ECDHE-RSA-AES suites.
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE-RSA-AES128-GCM-SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE-RSA-AES256-GCM-SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "ECDHE-RSA-AES128-SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "ECDHE-RSA-AES256-SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "ECDHE-RSA-AES128-SHA256"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "ECDHE-RSA-CHACHA20-POLY1305"
	// ECDHE-ECDSA-AES suites.
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE-ECDSA-AES128-GCM-SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE-ECDSA-AES256-GCM-SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "ECDHE-ECDSA-AES128-SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "ECDHE-ECDSA-AES256-SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "ECDHE-ECDSA-CHACHA20-POLY1305"
	// RSA static.
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "AES128-GCM-SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "AES256-GCM-SHA384"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "AES128-SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "AES256-SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "AES128-SHA256"
	// Weak / legacy.
	case 0x0004: // TLS_RSA_WITH_RC4_128_MD5
		return "RC4-MD5"
	case 0x0005: // TLS_RSA_WITH_RC4_128_SHA
		return "RC4-SHA"
	case 0xc011: // TLS_ECDHE_RSA_WITH_RC4_128_SHA
		return "ECDHE-RSA-RC4-SHA"
	case 0xc007: // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
		return "ECDHE-ECDSA-RC4-SHA"
	case 0x000a: // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		return "DES-CBC3-SHA"
	case 0xc008: // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
		return "ECDHE-ECDSA-DES-CBC3-SHA"
	case 0xc012: // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		return "ECDHE-RSA-DES-CBC3-SHA"
	// EXPORT.
	case 0x0003: // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		return "EXP-RC4-MD5"
	case 0x0006: // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
		return "EXP-RC2-CBC-MD5"
	case 0x0008: // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
		return "EXP-DES-CBC-SHA"
	// NULL (which Go's stdlib doesn't support but users might query for).
	case 0x0001: // TLS_RSA_WITH_NULL_MD5
		return "NULL-MD5"
	case 0x0002: // TLS_RSA_WITH_NULL_SHA
		return "NULL-SHA"
	}
	return ""
}
