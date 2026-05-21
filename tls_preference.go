package main

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"time"
)

// Cipher-suite preference — SSL Labs flagship column. Detects whether the
// server enforces its own cipher ordering or simply picks the client's first
// acceptable cipher. Method (the canonical SSL-Labs / sslyze trick):
//
//   1. Offer ciphers [A, B, C] — server picks X.
//   2. Offer ciphers [C, B, A] — server picks Y.
//
// If X == Y the server enforces server-side preference. If X != Y (and each
// equals the client's first acceptable cipher) the server defers to client
// preference. A server-preference posture is the recommended hardening — it
// prevents a malicious client from negotiating the weakest mutual cipher.
//
// Skipped when only one cipher is supported at the given version (no
// preference question), or when either probe fails to produce a ServerHello.

// cipherPreferenceResult records the verdict per TLS version.
type cipherPreferenceResult struct {
	TLSVersion string `json:"tls_version"`
	// Order is one of "server", "client", "indeterminate" (or "" when skipped).
	Order string `json:"order"`
	// ForwardPick and ReversePick name the cipher the server chose under each
	// offer. Surfaced so the user can spot weirder cases (e.g. server enforces
	// a *different* cipher than what either offer led with).
	ForwardPick string `json:"forward_pick,omitempty"`
	ReversePick string `json:"reverse_pick,omitempty"`
}

// probeCipherPreference detects cipher preference order at the given TLS
// version. Pass the list of ciphers already known to be supported (from
// enumerateCiphers) so we don't waste probes on rejected suites.
func probeCipherPreference(host string, port int, tlsVer uint16, supportedCiphers []uint16, timeout time.Duration) cipherPreferenceResult {
	res := cipherPreferenceResult{TLSVersion: tlsVersionNameForCode(tlsVer)}
	if len(supportedCiphers) < 2 {
		return res
	}
	if timeout > 1*time.Second {
		timeout = 1 * time.Second
	}

	forward := probeServerCipherChoice(host, port, tlsVer, supportedCiphers, timeout)
	if forward == 0 {
		return res
	}
	reversed := make([]uint16, len(supportedCiphers))
	for i, c := range supportedCiphers {
		reversed[len(supportedCiphers)-1-i] = c
	}
	reverse := probeServerCipherChoice(host, port, tlsVer, reversed, timeout)
	if reverse == 0 {
		return res
	}

	res.ForwardPick = cipherCodeName(forward)
	res.ReversePick = cipherCodeName(reverse)
	switch {
	case forward == reverse:
		res.Order = "server"
	case forward == supportedCiphers[0] && reverse == reversed[0]:
		res.Order = "client"
	default:
		res.Order = "indeterminate"
	}
	return res
}

// probeServerCipherChoice sends a ClientHello with the supplied cipher list at
// the given TLS version and returns the IANA code of the cipher the server
// chose (from ServerHello.cipher_suite). Returns 0 on parse failure or alert.
func probeServerCipherChoice(host string, port int, tlsVer uint16, ciphers []uint16, timeout time.Duration) uint16 {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := multiCipherClientHello(host, tlsVer, ciphers)
	if _, err := conn.Write(hello); err != nil {
		return 0
	}
	return readServerHelloCipher(conn)
}

// multiCipherClientHello builds a ClientHello offering the supplied cipher list
// in the order given (which is what makes preference detection work — see
// probeCipherPreference). Extensions match singleCipherClientHello so the
// server treats both probes identically except for cipher ordering.
func multiCipherClientHello(host string, tlsVer uint16, ciphers []uint16) []byte {
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, 0x05, 0x03,
		0x08, 0x04, 0x08, 0x05, 0x08, 0x07,
		0x04, 0x01, 0x05, 0x01,
		0x02, 0x01, 0x02, 0x03,
	)

	legacyVer := tlsVer
	if tlsVer == 0x0304 {
		legacyVer = 0x0303
		extensions = append(extensions, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
		extensions = append(extensions, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00)
	}
	extLen := len(extensions)

	cipherBytes := make([]byte, 0, len(ciphers)*2)
	for _, c := range ciphers {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}

	body := []byte{byte(legacyVer >> 8), byte(legacyVer & 0xff)}
	body = append(body, rnd...)
	body = append(body, 0x00)
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, byte(legacyVer >> 8), byte(legacyVer & 0xff), byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// readServerHelloCipher reads TLS records from conn until it sees a
// ServerHello, then returns the cipher_suite field. Returns 0 on alert,
// read error, or parse failure.
func readServerHelloCipher(conn net.Conn) uint16 {
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return 0
		}
		recType := hdr[0]
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return 0
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return 0
		}
		if recType == 0x15 {
			return 0
		}
		if recType != 0x16 {
			continue
		}
		for i := 0; i+4 <= len(body); {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			end := i + 4 + hsLen
			if end > len(body) {
				return 0
			}
			if hsType == 0x02 {
				return serverHelloCipherSuite(body[i+4 : end])
			}
			i = end
		}
	}
}

// serverHelloCipherSuite extracts the cipher_suite field from a ServerHello
// body. Layout: version(2) + random(32) + session_id_len(1) + session_id(N) +
// cipher_suite(2) + compression_method(1) + extensions(...).
func serverHelloCipherSuite(body []byte) uint16 {
	if len(body) < 35 {
		return 0
	}
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+2 > len(body) {
		return 0
	}
	return uint16(body[off])<<8 | uint16(body[off+1])
}

// tlsVersionNameForCode is the inverse of the wire-format mapping used by
// tlsVersionName — it accepts a uint16 version code and returns a human
// readable label like "TLS 1.2".
func tlsVersionNameForCode(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return ""
}
