package main

import (
	"net"
	"strconv"
	"time"
)

// computeJA4SFromHandshake sends a single TLS 1.3 ClientHello to the
// target and computes the JA4S server fingerprint from the resulting
// ServerHello. This is a dedicated probe (not piggybacking on JARM's
// 10 probes) so we get a deterministic fingerprint based on a
// well-known client offer.
func computeJA4SFromHandshake(host string, port int, timeout time.Duration) ja4Result {
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ja4Result{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build a stable TLS 1.3 ClientHello via the JARM TLS_1.3_FORWARD probe
	// spec — guaranteed-modern offer that exercises the full extension set.
	spec := jarm10Probes[6] // TLS_1.3_FORWARD
	hello := buildJARMClientHello(host, spec)
	if _, err := conn.Write(hello); err != nil {
		return ja4Result{}
	}
	body := readServerHelloBody(conn)
	if body == nil {
		return ja4Result{}
	}
	// Extract ALPN from ServerHello extensions for the JA4S a-component.
	ext := serverHelloExtensions(body)
	alpn := alpnFromExtensions(ext)
	return computeJA4S(body, "h2", alpn)
}
