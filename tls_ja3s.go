package main

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// JA3S — server-side TLS fingerprint, complement to JA3 (client) and JARM
// (active multi-probe). Computed from the server's selections in a SINGLE
// standard ServerHello:
//
//   md5( SSLVersionPicked, CipherSuitePicked, Extensions )
//
// All three fields are decimal IDs (not hex). Extensions is a dash-separated
// list of the extension type IDs the server included in its response, in
// observed order.
//
// JA3S is the lighter-weight cousin of JARM — one probe instead of ten,
// captures only the server's response to OUR specific ClientHello rather
// than synthesising 10 variant hellos. Different signal but valuable
// in combination: identical JARM + different JA3S means same TLS stack
// reacting differently to the same client.
//
// Reference: https://github.com/salesforce/ja3 (JA3S section)

// ja3sResult is the JA3S fingerprint + the raw fields.
type ja3sResult struct {
	Hash    string `json:"hash"`     // 32-char lowercase MD5 hex
	Raw     string `json:"raw"`      // "version,cipher,ext-ext-ext"
	Version uint16 `json:"version"`
	Cipher  uint16 `json:"cipher"`
	ExtCount int   `json:"ext_count"`
}

// computeJA3S builds the JA3S fingerprint from a server's ServerHello.
// `body` is the ServerHello body bytes (after the 4-byte handshake header).
func computeJA3S(body []byte) ja3sResult {
	var out ja3sResult
	if len(body) < 35 {
		return out
	}
	out.Version = uint16(body[0])<<8 | uint16(body[1])
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+2 > len(body) {
		return out
	}
	out.Cipher = uint16(body[off])<<8 | uint16(body[off+1])

	ext := serverHelloExtensions(body)
	var extIDs []string
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			break
		}
		extIDs = append(extIDs, decimalUint16(extType))
		i = end
	}
	out.ExtCount = len(extIDs)
	out.Raw = decimalUint16(out.Version) + "," + decimalUint16(out.Cipher) + "," + strings.Join(extIDs, "-")
	sum := md5.Sum([]byte(out.Raw))
	out.Hash = hex.EncodeToString(sum[:])
	return out
}

// md5sum returns the lowercase hex MD5 of s. Used by JA3S.
func md5sum(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func decimalUint16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + byte(v%10)
		v /= 10
	}
	return string(buf[i:])
}

// ja3sHeadline returns a short hint-line label.
func ja3sHeadline(j ja3sResult) string {
	if j.Hash == "" {
		return ""
	}
	return "JA3S: " + j.Hash[:8] + "…"
}
