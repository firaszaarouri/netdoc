package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

// http3Result records what a real QUIC handshake against the target told us.
// Distinguishes "the server advertises h3 via Alt-Svc" (cheap, header inspection)
// from "the server actually completes a QUIC handshake and speaks h3" (real
// probe). curl, hurl, oha and httpx all do the real probe — netdoc used to
// only detect advertising; this closes the gap.
type http3Result struct {
	Supported   bool    `json:"supported"`
	ALPN        string  `json:"alpn,omitempty"`
	Version     string  `json:"quic_version,omitempty"`
	HandshakeMS float64 `json:"handshake_ms,omitempty"`
	Used0RTT    bool    `json:"used_0rtt,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// probeHTTP3 opens a QUIC connection to host:port and verifies the server
// completes the handshake with an h3 ALPN. Caps the wait at 2 seconds — for
// servers that advertise h3 but block UDP, we'd otherwise wait the full
// d.timeout (5s default) for the timeout to fire.
func probeHTTP3(host string, port int, timeout time.Duration) http3Result {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "h3-29", "h3-32"},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
	}

	start := time.Now()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return http3Result{Error: tidyErr(err)}
	}
	state := conn.ConnectionState()
	res := http3Result{
		Supported:   true,
		ALPN:        state.TLS.NegotiatedProtocol,
		Version:     fmt.Sprintf("0x%08x", uint32(state.Version)),
		HandshakeMS: ms(time.Since(start)),
		Used0RTT:    state.Used0RTT,
	}
	_ = conn.CloseWithError(0, "")
	return res
}
