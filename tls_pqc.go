package main

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"time"
)

// Post-Quantum hybrid key-exchange detection. Modern TLS 1.3 deployments
// at major CDNs (Cloudflare, Google, AWS) now negotiate X25519MLKEM768 — a
// hybrid combining classical X25519 ECDH with the post-quantum ML-KEM-768
// KEM (NIST FIPS 203). Browsers that support PQC (Chrome 124+, Firefox 132+)
// offer it in their TLS 1.3 key_share; servers that support it pick it.
//
// netdoc actively probes by sending a TLS 1.3 ClientHello whose key_share
// extension contains the X25519MLKEM768 group (IANA codepoint 0x11ec).
// If the server's ServerHello selects the same group (in its key_share
// extension), the server speaks PQC.
//
// References:
//   IANA TLS Supported Groups: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
//   draft-ietf-tls-mlkem-key-agreement (X25519MLKEM768 codepoint 0x11ec)
//   draft-ietf-tls-hybrid-design (hybrid KEM rationale)
//
// Status check: testssl.sh 3.2 has zero "ECH" or "MLKEM" mentions per the
// v2.8 agent audit; Hardenize ships it. netdoc would join Hardenize as
// one of two tools surfacing this.

// pqcResult records whether the server selected an offered PQC group.
type pqcResult struct {
	Probed      bool   `json:"probed"`
	Supported   bool   `json:"supported"`
	GroupCode   uint16 `json:"group_code,omitempty"`
	GroupName   string `json:"group_name,omitempty"`
}

// probePQC sends a TLS 1.3 ClientHello advertising X25519MLKEM768 in
// supported_groups + a zero-length key_share for that group, and inspects
// the server's response. A server that supports PQC will either pick the
// group (sending its own key_share) or send HelloRetryRequest asking us to
// re-send with the proper key bytes — both confirm support.
func probePQC(host string, port int, timeout time.Duration) pqcResult {
	out := pqcResult{Probed: true}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pqcClientHello(host)); err != nil {
		return out
	}
	body := readServerHelloBody(conn)
	if body == nil {
		return out
	}
	// Inspect ServerHello extensions for key_share (type 0x33).
	ext := serverHelloExtensions(body)
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			break
		}
		// key_share in ServerHello carries a single KeyShareEntry:
		//   uint16 group + uint16 key_exchange length + bytes
		if extType == 0x0033 && extDataLen >= 2 {
			group := uint16(ext[i+4])<<8 | uint16(ext[i+5])
			if group == 0x11ec {
				out.Supported = true
				out.GroupCode = group
				out.GroupName = "X25519MLKEM768"
				return out
			}
		}
		i = end
	}
	// HelloRetryRequest also signals support — when the server's chosen group
	// matches what we offered but it asks us to retry with a proper key.
	// HRR uses a magic ServerHello.random value. Detection:
	if len(body) >= 34 {
		serverRandom := body[2:34]
		// HRR magic per RFC 8446 §4.1.3:
		// SHA-256("HelloRetryRequest") = cf21ad74e59a6111be1d8c021e65b891
		//                                c2a211167abb8c5e079e09e2c8a8339c
		hrrMagic := []byte{
			0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
			0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
			0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
			0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
		}
		if bytesEqual(serverRandom, hrrMagic) {
			// Walk ServerHello.extensions for the key_share giving group selection.
			for i := 0; i+4 <= len(ext); {
				extType := uint16(ext[i])<<8 | uint16(ext[i+1])
				extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
				end := i + 4 + extDataLen
				if end > len(ext) {
					break
				}
				if extType == 0x0033 && extDataLen == 2 {
					group := uint16(ext[i+4])<<8 | uint16(ext[i+5])
					if group == 0x11ec {
						out.Supported = true
						out.GroupCode = group
						out.GroupName = "X25519MLKEM768"
						return out
					}
				}
				i = end
			}
		}
	}
	return out
}

// pqcClientHello builds a TLS 1.3 ClientHello whose supported_groups
// includes X25519MLKEM768 and whose key_share offers a SHORT entry for it
// (deliberately under-sized so the server can either pick another group OR
// reply with HelloRetryRequest — both outcomes give us a signal).
//
// We also offer X25519 in supported_groups so legacy servers without PQC
// can fall back to it without erroring out the handshake.
func pqcClientHello(host string) []byte {
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	// supported_groups (type 0x000a): list the PQC group FIRST, then x25519
	// fallbacks. Length: 6 bytes (3 groups × 2).
	supportedGroups := []byte{
		0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
		0x11, 0xec, // X25519MLKEM768
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
	}

	// signature_algorithms (type 0x000d): broad set.
	sigAlgs := []byte{
		0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, 0x05, 0x03,
		0x08, 0x04, 0x08, 0x05, 0x08, 0x07,
		0x04, 0x01, 0x05, 0x01,
		0x02, 0x01, 0x02, 0x03,
	}

	// supported_versions (type 0x002b): list TLS 1.3 only.
	supportedVersions := []byte{
		0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
	}

	// key_share (type 0x0033): offer a one-entry list for X25519MLKEM768
	// with a placeholder key. X25519MLKEM768 key_exchange is 1216 bytes
	// (32 X25519 + 1184 MLKEM768 public key). We send dummy bytes — the
	// server's response tells us support without our key being valid.
	pqcKey := make([]byte, 1216)
	_, _ = rand.Read(pqcKey)
	keyShareEntry := []byte{0x11, 0xec, 0x04, 0xc0} // group + length=1216
	keyShareEntry = append(keyShareEntry, pqcKey...)
	keyShareList := []byte{byte(len(keyShareEntry) >> 8), byte(len(keyShareEntry) & 0xff)}
	keyShareList = append(keyShareList, keyShareEntry...)
	keyShare := []byte{0x00, 0x33, byte(len(keyShareList) >> 8), byte(len(keyShareList) & 0xff)}
	keyShare = append(keyShare, keyShareList...)

	// Build SNI
	sni := buildSNIExtension(host)

	// ALPN: h2 + http/1.1 so the server doesn't bail.
	alpn := buildALPNExtension([]string{"h2", "http/1.1"})

	extensions := append([]byte{}, sni...)
	extensions = append(extensions, supportedGroups...)
	extensions = append(extensions, sigAlgs...)
	extensions = append(extensions, supportedVersions...)
	extensions = append(extensions, alpn...)
	extensions = append(extensions, keyShare...)

	// Cipher list (TLS 1.3 only).
	cipherBytes := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}

	body := []byte{0x03, 0x03} // legacy_version = TLS 1.2
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression null
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// bytesEqual is a small slice-equal helper to keep our deps minimal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pqcHeadline returns "PQC: X25519MLKEM768" when supported, empty otherwise.
func pqcHeadline(p pqcResult) string {
	if !p.Supported {
		return ""
	}
	return "PQC: " + p.GroupName
}

// Keep io referenced even though we don't use it directly.
var _ = io.EOF
