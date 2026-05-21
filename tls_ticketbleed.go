package main

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"time"
)

// Ticketbleed (CVE-2016-9244) — F5 BIG-IP information disclosure. Affected
// versions return 31 bytes of uninitialized server memory when the client
// sends a TLS ClientHello whose session_id field is shorter than 32 bytes.
// The server echoes back what it THINKS the session_id was (padded to 32
// bytes with leaked memory).
//
// The probe: send a ClientHello with a session_id of 1 specific marker byte
// (e.g. 0xAA). A patched server either rejects the short session_id outright
// OR generates a new session_id; either way, it does NOT echo back our
// marker. A vulnerable F5 server echoes back the 1-byte marker + 31 bytes
// of memory we shouldn't see.
//
// We check the ServerHello's echoed session_id:
//   - First byte == our marker → ServerHello echoed our session_id back (vulnerable signal)
//   - Length 32 (which it always is for F5) AND first byte == marker → vulnerable
//   - First byte ≠ marker → server generated its own session_id (safe)
//
// References:
//   https://blog.filippo.io/finding-ticketbleed/
//   https://github.com/FiloSottile/Ticketbleed
//   https://nmap.org/nsedoc/scripts/tls-ticketbleed.html

func probeTicketbleed(host string, port int, timeout time.Duration) bool {
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Marker byte — 0xAA is uncommon enough that a random server-side session_id
	// is overwhelmingly unlikely to start with it (1/256 random match).
	const marker byte = 0xAA
	hello := ticketbleedClientHello(host, marker)
	if _, err := conn.Write(hello); err != nil {
		return false
	}

	body := readServerHelloBody(conn)
	if body == nil {
		return false
	}
	// ServerHello body: version(2) + random(32) + session_id_len(1) + session_id(N)
	if len(body) < 35 {
		return false
	}
	sidLen := int(body[34])
	if sidLen != 32 {
		// F5 always returns a 32-byte session_id on vulnerable versions.
		// A different length means non-F5 / patched.
		return false
	}
	if 35+sidLen > len(body) {
		return false
	}
	// VULNERABLE iff the server echoed back our 1-byte marker at offset 0.
	return body[35] == marker
}

// ticketbleedClientHello builds a TLS 1.1 ClientHello with a session_id field
// that's only 1 byte long (the marker). Real implementations either ignore
// short session_ids or generate a fresh one; F5 vulnerable to Ticketbleed
// pads the response session_id from server memory.
//
// We use TLS 1.1 deliberately — the bug exists in 1.1 + 1.2, and 1.1 has
// the simplest ClientHello with no required extensions beyond SNI.
func ticketbleedClientHello(host string, marker byte) []byte {
	cipherSuites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c,
		0xc013, 0xc014, 0xc009, 0xc00a,
		0x009c, 0x009d, 0x002f, 0x0035,
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
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
	extLen := len(extensions)

	body := []byte{0x03, 0x02} // TLS 1.1
	body = append(body, rnd...)
	body = append(body, 0x01, marker) // session_id length = 1, value = marker
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x02, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// Suppress unused-import warning by referencing io.
var _ = io.EOF
