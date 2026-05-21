package main

import (
	"crypto/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

// ALPN full enumeration — probes each known ALPN protocol identifier with a
// dedicated TLS 1.2 ClientHello carrying ONE ALPN entry. If the server
// completes ServerHello AND selects that protocol via its own ALPN extension,
// the protocol is supported.
//
// Why one-cipher-style enumeration rather than offering them all at once: a
// single multi-ALPN ClientHello tells us only the server's *first preference*,
// not the full set it would accept. The per-protocol probe is the same trick
// SSL Labs and nmap's tls-alpn NSE script use.
//
// Skipped on TLS 1.3-only servers (they still answer to TLS 1.2 handshakes,
// but a small handful refuse a 1.2 offer entirely — in that case the probe
// just returns an empty list and a higher-level caller can read the standard
// handshake's NegotiatedProtocol instead).

// knownALPNProtocols is the curated list of protocol IDs we probe. Sources:
// IANA TLS ALPN Protocol IDs registry. We deliberately skip ALPN values that
// only apply to non-HTTPS contexts on non-443 ports (mqtt, dot, doq) when
// scanning :443 — but include them at request because servers proxying for
// those uses occasionally do answer on 443.
var knownALPNProtocols = []string{
	"h2",          // HTTP/2 over TLS — RFC 7540
	"http/1.1",    // HTTP/1.1 — RFC 7230
	"http/1.0",    // HTTP/1.0 (rare in 2026 but still observed)
	"h3",          // HTTP/3 over QUIC — RFC 9114 (advertised on TLS but only used over QUIC)
	"h3-29",       // HTTP/3 draft 29 (legacy QUIC stacks still negotiate it)
	"acme-tls/1",  // ACME TLS-ALPN-01 — RFC 8737 (Let's Encrypt challenge)
	"dot",         // DNS-over-TLS — RFC 7858
	"doq",         // DNS-over-QUIC — RFC 9250
	"smtp",        // RFC 8314 — submission over TLS (port 587 STARTTLS)
	"imap",        // RFC 8314
	"pop3",        // RFC 8314
	"managesieve", // RFC 5804
	"mqtt",        // RFC 7252 mappings
	"ftp",         // RFC 4217 — FTP over TLS
	"xmpp-client", // RFC 7590
	"xmpp-server", // RFC 7590
	"webrtc",      // WebRTC media (RFC 8835 reference)
	"c-webrtc",    // confidential WebRTC
	"coap",        // RFC 7252
	"stun.turn",   // RFC 7350 — STUN/TURN over TLS
	"stun.nat-discovery",
	"sunrpc",
	"irc",
	"nntp",
	"radius/1.0", // RFC 6614
	"radius/1.1",
}

// probeALPN enumerates which ALPN protocol IDs the server accepts. Concurrent
// across protocols, bounded by `sem` to avoid hammering the target. Returns
// the set of accepted protocols in registry order.
func probeALPN(host string, port int, timeout time.Duration) []string {
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}

	type result struct {
		proto string
		ok    bool
	}
	out := make(chan result, len(knownALPNProtocols))
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, proto := range knownALPNProtocols {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok := probeOneALPN(host, port, p, timeout)
			out <- result{proto: p, ok: ok}
		}(proto)
	}
	go func() { wg.Wait(); close(out) }()

	got := make(map[string]bool, len(knownALPNProtocols))
	for r := range out {
		if r.ok {
			got[r.proto] = true
		}
	}
	var accepted []string
	for _, p := range knownALPNProtocols {
		if got[p] {
			accepted = append(accepted, p)
		}
	}
	return accepted
}

// probeOneALPN sends a TLS 1.2 ClientHello offering exactly one ALPN protocol
// and returns true iff the server's ServerHello echoes that protocol in its
// own ALPN extension. Servers without ALPN support reply with no ALPN
// extension (false). Servers that refuse the protocol reply with no_application_
// protocol alert(120) or just leave the extension out (false).
func probeOneALPN(host string, port int, proto string, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := alpnClientHello(host, proto)
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	picked := readServerHelloALPN(conn)
	return picked == proto
}

// alpnClientHello builds a TLS 1.2 ClientHello offering a sensible cipher set
// plus exactly ONE ALPN protocol entry. The single-protocol offer is what
// lets us tell "server supports proto X" from "server uses proto X by
// default" — the only legal ServerHello here is one that echoes our offer.
func alpnClientHello(host string, proto string) []byte {
	cipherSuites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c,
		0xcca8, 0xcca9,
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
	extensions = append(extensions, buildALPNExtension([]string{proto})...)

	extLen := len(extensions)

	body := []byte{0x03, 0x03}
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
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// buildALPNExtension constructs an application_layer_protocol_negotiation
// extension (RFC 7301, type 0x0010) carrying the supplied protocol list. Each
// entry is encoded as 1-byte-length-prefix + protocol bytes.
func buildALPNExtension(protos []string) []byte {
	var protoList []byte
	for _, p := range protos {
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, []byte(p)...)
	}
	listLen := len(protoList)
	out := []byte{0x00, 0x10, byte((listLen + 2) >> 8), byte((listLen + 2) & 0xff)}
	out = append(out, byte(listLen>>8), byte(listLen&0xff))
	return append(out, protoList...)
}

// readServerHelloALPN reads TLS records until it sees a ServerHello, then
// parses ServerHello.extensions for an ALPN extension and returns the first
// protocol entry. Returns "" if no ALPN extension is present or any parse
// step fails.
func readServerHelloALPN(conn net.Conn) string {
	body := readServerHelloBody(conn)
	if body == nil {
		return ""
	}
	ext := serverHelloExtensions(body)
	if ext == nil {
		return ""
	}
	return alpnFromExtensions(ext)
}

// readServerHelloBody reads records from conn until it returns the body bytes
// of the first ServerHello it encounters, or nil on any failure.
func readServerHelloBody(conn net.Conn) []byte {
	for {
		hdr := make([]byte, 5)
		if _, err := readN(conn, hdr); err != nil {
			return nil
		}
		recType := hdr[0]
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return nil
		}
		recBody := make([]byte, recLen)
		if _, err := readN(conn, recBody); err != nil {
			return nil
		}
		if recType == 0x15 {
			return nil
		}
		if recType != 0x16 {
			continue
		}
		for i := 0; i+4 <= len(recBody); {
			hsType := recBody[i]
			hsLen := int(recBody[i+1])<<16 | int(recBody[i+2])<<8 | int(recBody[i+3])
			end := i + 4 + hsLen
			if end > len(recBody) {
				return nil
			}
			if hsType == 0x02 {
				return recBody[i+4 : end]
			}
			i = end
		}
	}
}

// readN is a tiny io.ReadFull shim that lets the alpn/extension readers share
// shorter import lists (importing io into multiple files is fine but cluttered).
func readN(c net.Conn, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := c.Read(p[got:])
		if n > 0 {
			got += n
		}
		if err != nil {
			if got == len(p) {
				return got, nil
			}
			return got, err
		}
	}
	return got, nil
}

// serverHelloExtensions returns the extension-list bytes from a ServerHello
// body, or nil if no extensions are present. Layout:
//   version(2) + random(32) + sid_len(1) + sid(N) + cipher(2) + compression(1)
//   + extensions_len(2) + extensions(N).
func serverHelloExtensions(body []byte) []byte {
	if len(body) < 35 {
		return nil
	}
	sidLen := int(body[34])
	off := 35 + sidLen + 2 + 1
	if off+2 > len(body) {
		return nil
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if off+extLen > len(body) {
		return nil
	}
	return body[off : off+extLen]
}

// alpnFromExtensions scans the extension list for an ALPN extension (type
// 0x0010) and returns the first protocol entry it contains, or "" if absent.
func alpnFromExtensions(ext []byte) string {
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			return ""
		}
		if extType == 0x0010 {
			data := ext[i+4 : end]
			if len(data) < 3 {
				return ""
			}
			// data[0..2] = list length, then 1-byte-len-prefixed entries.
			plen := int(data[2])
			if 3+plen > len(data) {
				return ""
			}
			return string(data[3 : 3+plen])
		}
		i = end
	}
	return ""
}
