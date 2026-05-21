package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// JA4 + JA4S TLS fingerprints — Foxio's 2023 successor to JA3/JARM.
//
// Why JA4 over JA3:
//   - JA3 is order-dependent on cipher/extension lists; JA4 sorts → stable
//     fingerprints despite client implementation reordering
//   - JA4 separates cipher/extension components → matches against partial
//     fingerprints; JA3 is one opaque MD5
//   - JA4 includes ALPN + sig-algs explicitly → catches more variation
//   - JA4 prefix is human-readable (t13d1715h2) — operators can scan
//     fingerprints by eye for protocol/version/ALPN
//   - JA3 uses MD5; JA4 uses SHA-256 (truncated to 12 hex)
//
// Format (38 chars total for TLS):
//   a_b_c
// where:
//   a = "q" or "t" (QUIC or TCP) + TLS version 2 digits + "d" or "i"
//       (SNI domain or IP) + cipher count 2 digits + extension count 2
//       digits + first ALPN value (2 chars or "00")
//   b = first 12 hex of SHA-256 of comma-separated sorted ciphers
//   c = first 12 hex of SHA-256 of comma-separated sorted-non-grease
//       extensions ("," sorted-sigalgs)
//
// Example: t13d1715h2_5b57614c22b0_3d5424432f57
//
// JA4S (server fingerprint) format (~23 chars):
//   a_b_c
// where:
//   a = "q" or "t" + TLS version + extension count + ALPN value (2 chars)
//   b = chosen cipher (4 hex)
//   c = first 12 hex of SHA-256 of comma-separated sorted extensions
//
// References:
//   https://github.com/FoxIO-LLC/ja4
//   https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//   https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md

// ja4Result records both client and server fingerprints.
type ja4Result struct {
	JA4  string `json:"ja4,omitempty"`  // would describe netdoc's own ClientHello
	JA4S string `json:"ja4s,omitempty"` // describes the server's ServerHello
}

// computeJA4S builds the JA4S server fingerprint from a captured
// ServerHello body (after the 4-byte handshake header).
func computeJA4S(body []byte, protocol string, alpn string) ja4Result {
	var out ja4Result
	if len(body) < 35 {
		return out
	}
	tlsVer := uint16(body[0])<<8 | uint16(body[1])
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+2 > len(body) {
		return out
	}
	cipher := uint16(body[off])<<8 | uint16(body[off+1])

	ext := serverHelloExtensions(body)
	// supported_versions extension (0x002b) tells us real TLS version on TLS 1.3.
	if sv := supportedVersionsFromExtensions(ext); sv != 0 {
		tlsVer = sv
	}
	// Collect extension type IDs (excluding GREASE).
	var extIDs []uint16
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			break
		}
		if !isGREASE(extType) {
			extIDs = append(extIDs, extType)
		}
		i = end
	}
	// JA4S a-component: t/q + version + extension-count + alpn1+alpn2
	verStr := ja4VersionString(tlsVer)
	transport := "t" // TCP — we don't yet detect QUIC handshakes
	if protocol == "h3" || protocol == "h3-29" {
		transport = "q"
	}
	alpnComponent := ja4ALPNComponent(alpn)
	a := transport + verStr + fmtTwoDigit(len(extIDs)) + alpnComponent

	// JA4S b-component: chosen cipher (4 hex)
	b := uint16hex(cipher)

	// JA4S c-component: SHA-256-12 of comma-separated extension IDs in
	// the ORDER seen (per JA4S spec, NOT sorted — order is informative
	// for server fingerprinting).
	var extStrs []string
	for _, e := range extIDs {
		extStrs = append(extStrs, uint16hex(e))
	}
	c := sha256_12(strings.Join(extStrs, ","))

	out.JA4S = a + "_" + b + "_" + c
	return out
}

// computeJA4FromClientHello builds the CLIENT JA4 from a ClientHello we
// observed (e.g. in a tcpdump capture). For our use we don't generally
// fingerprint our own hello, but the function is provided for symmetry.
//
// For netdoc's purposes we mainly compute JA4S (server side), since that's
// the fingerprint we have data for from probing.
func computeJA4FromClientHello(helloBody []byte, sni string) string {
	if len(helloBody) < 38 {
		return ""
	}
	// legacy_version = helloBody[0..2]
	tlsVer := uint16(helloBody[0])<<8 | uint16(helloBody[1])
	sidLen := int(helloBody[34])
	off := 35 + sidLen
	if off+2 > len(helloBody) {
		return ""
	}
	cipherListLen := int(helloBody[off])<<8 | int(helloBody[off+1])
	off += 2
	cipherListEnd := off + cipherListLen
	if cipherListEnd > len(helloBody) {
		return ""
	}
	var ciphers []uint16
	for i := off; i+2 <= cipherListEnd; i += 2 {
		c := uint16(helloBody[i])<<8 | uint16(helloBody[i+1])
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	off = cipherListEnd
	if off+1 > len(helloBody) {
		return ""
	}
	compLen := int(helloBody[off])
	off += 1 + compLen
	if off+2 > len(helloBody) {
		return ""
	}
	extLen := int(helloBody[off])<<8 | int(helloBody[off+1])
	off += 2
	if off+extLen > len(helloBody) {
		return ""
	}
	ext := helloBody[off : off+extLen]

	var extIDs []uint16
	var sigAlgs []uint16
	var alpn string
	hasSNI := false
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			break
		}
		if !isGREASE(extType) {
			extIDs = append(extIDs, extType)
		}
		switch extType {
		case 0x0000:
			hasSNI = true
		case 0x000d:
			data := ext[i+4 : end]
			if len(data) >= 2 {
				slen := int(data[0])<<8 | int(data[1])
				for j := 2; j+2 <= 2+slen && j+2 <= len(data); j += 2 {
					sigAlgs = append(sigAlgs, uint16(data[j])<<8|uint16(data[j+1]))
				}
			}
		case 0x0010:
			data := ext[i+4 : end]
			if len(data) > 3 {
				plen := int(data[2])
				if 3+plen <= len(data) {
					alpn = string(data[3 : 3+plen])
				}
			}
		case 0x002b:
			data := ext[i+4 : end]
			if len(data) >= 3 {
				cnt := int(data[0])
				for j := 1; j+2 <= 1+cnt && j+2 <= len(data); j += 2 {
					v := uint16(data[j])<<8 | uint16(data[j+1])
					if v > tlsVer {
						tlsVer = v
					}
				}
			}
		}
		i = end
	}
	verStr := ja4VersionString(tlsVer)
	transport := "t"
	sniMarker := "d"
	if !hasSNI {
		sniMarker = "i"
	}
	_ = sni
	alpnComponent := ja4ALPNComponent(alpn)
	a := transport + verStr + sniMarker + fmtTwoDigit(len(ciphers)) + fmtTwoDigit(len(extIDs)) + alpnComponent

	// b-component: SHA-256-12 of SORTED cipher list
	cipherStrs := make([]string, len(ciphers))
	for i, c := range ciphers {
		cipherStrs[i] = uint16hex(c)
	}
	sort.Strings(cipherStrs)
	b := sha256_12(strings.Join(cipherStrs, ","))

	// c-component: SHA-256-12 of SORTED non-grease extensions (without
	// SNI / ALPN per spec) + sigalgs appended in ORDER seen
	var filteredExts []uint16
	for _, e := range extIDs {
		// SNI (0x0000) and ALPN (0x0010) ARE in the count but excluded from hash
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		filteredExts = append(filteredExts, e)
	}
	extStrs := make([]string, len(filteredExts))
	for i, e := range filteredExts {
		extStrs[i] = uint16hex(e)
	}
	sort.Strings(extStrs)
	// Append sigalgs in original order, comma-separated.
	sigStrs := make([]string, len(sigAlgs))
	for i, s := range sigAlgs {
		sigStrs[i] = uint16hex(s)
	}
	cInput := strings.Join(extStrs, ",")
	if len(sigStrs) > 0 {
		cInput += "_" + strings.Join(sigStrs, ",")
	}
	c := sha256_12(cInput)
	return a + "_" + b + "_" + c
}

// ja4VersionString maps a TLS version uint16 to its 2-digit JA4 prefix:
//   0x0304 → "13"
//   0x0303 → "12"
//   0x0302 → "11"
//   0x0301 → "10"
//   0x0300 → "s3"
//   0x0200 → "s2"
func ja4VersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0200:
		return "s2"
	}
	return "00"
}

// ja4ALPNComponent returns the 2-char ALPN identifier per JA4 spec:
//   h2     → "h2"
//   http/1.1 → "h1"
//   h3     → "h3"
//   acme-tls/1 → "a1" (first + last char of the protocol)
//   any other  → first+last char of the protocol
//   no ALPN → "00"
func ja4ALPNComponent(alpn string) string {
	if alpn == "" {
		return "00"
	}
	switch alpn {
	case "h2":
		return "h2"
	case "h3":
		return "h3"
	case "http/1.1":
		return "h1"
	case "http/1.0":
		return "h0"
	}
	// Generic rule: first char + last char of protocol identifier.
	if len(alpn) == 1 {
		return string(alpn[0]) + string(alpn[0])
	}
	return string(alpn[0]) + string(alpn[len(alpn)-1])
}

// fmtTwoDigit zero-pads an int to 2 digits per JA4 spec; values > 99 cap at 99.
func fmtTwoDigit(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

// sha256_12 returns the first 12 hex chars of SHA-256(input).
func sha256_12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// isGREASE reports whether a codepoint is a TLS GREASE value (RFC 8701).
// GREASE values follow the pattern 0x?A?A where ? is any hex digit.
func isGREASE(v uint16) bool {
	low := byte(v & 0xff)
	high := byte((v >> 8) & 0xff)
	return (low & 0x0f) == 0x0a && low == high
}

// ja4Headline returns the JA4S server fingerprint short label.
func ja4Headline(r ja4Result) string {
	if r.JA4S == "" {
		return ""
	}
	// Display first 12 chars of JA4S for hint (rest in JSON).
	full := r.JA4S
	if len(full) > 12 {
		return "JA4S: " + full[:12] + "…"
	}
	return "JA4S: " + full
}
