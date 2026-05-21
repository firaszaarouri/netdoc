package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// dnsTransport describes how DNS queries should be sent. The zero value
// (nil pointer) means "use plain UDP to 1.1.1.1" — the same fallback the
// supplementary-record lookups have used since v1.5. With a non-nil
// transport, callers can route every query over UDP/TCP/DoT/DoH/DoQ to
// any resolver.
type dnsTransport struct {
	Mode   string // "udp" | "tcp" | "dot" | "doh" | "doq"
	Server string // "1.1.1.1:53" or "https://cloudflare-dns.com/dns-query"
}

func (t *dnsTransport) String() string {
	if t == nil {
		return "udp:1.1.1.1:53"
	}
	return t.Mode + "://" + t.Server
}

// parseDNSTransport interprets the --dns flag value and returns a transport.
// Accepts: "system" (returns nil), "udp", "tcp", "dot", "doh", "doq", each
// optionally followed by ":server". For DoH the server is a full https URL;
// for DoQ the server is host[:port] (port defaults to 853 per RFC 9250).
func parseDNSTransport(spec string) (*dnsTransport, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "system" {
		return nil, nil
	}

	// DoH carries an "https://" URL after the prefix, so peel it off first.
	// Bare "doh" (no suffix) also routes here so the default Cloudflare
	// endpoint can be selected without typing the URL.
	if spec == "doh" || strings.HasPrefix(spec, "doh:") {
		server := strings.TrimPrefix(spec, "doh")
		server = strings.TrimPrefix(server, ":")
		if server == "" {
			server = "https://cloudflare-dns.com/dns-query"
		}
		return &dnsTransport{Mode: "doh", Server: server}, nil
	}

	parts := strings.SplitN(spec, ":", 2)
	mode := parts[0]
	server := ""
	if len(parts) == 2 {
		server = parts[1]
	}

	switch mode {
	case "udp", "tcp":
		if server == "" {
			server = "1.1.1.1"
		}
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "53")
		}
	case "dot":
		if server == "" {
			server = "1.1.1.1"
		}
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "853")
		}
	case "doq":
		if server == "" {
			// Quad9's DoQ has been stable since DoQ shipped; Cloudflare's
			// 1.1.1.1 DoQ has been flaky from some networks. Picking the
			// reliably-working default.
			server = "dns.quad9.net"
		}
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "853")
		}
	default:
		return nil, fmt.Errorf("unknown DNS transport %q (use system, udp, tcp, dot, doh or doq)", mode)
	}
	return &dnsTransport{Mode: mode, Server: server}, nil
}

// dnsExchange sends the given DNS message via the configured transport and
// returns the full response so callers can inspect flags like AuthenticatedData
// (the AD bit) or the Authority/Additional sections.
func dnsExchange(m *dns.Msg, transport *dnsTransport, timeout time.Duration) (*dns.Msg, error) {
	if transport == nil {
		transport = &dnsTransport{Mode: "udp", Server: "1.1.1.1:53"}
	}
	switch transport.Mode {
	case "udp", "tcp":
		c := &dns.Client{Net: transport.Mode, Timeout: timeout}
		r, _, err := c.Exchange(m, transport.Server)
		return r, err
	case "dot":
		host, _, _ := net.SplitHostPort(transport.Server)
		c := &dns.Client{
			Net:       "tcp-tls",
			Timeout:   timeout,
			TLSConfig: &tls.Config{ServerName: host},
		}
		r, _, err := c.Exchange(m, transport.Server)
		return r, err
	case "doh":
		return dohExchange(m, transport.Server, timeout)
	case "doq":
		return doqExchange(m, transport.Server, timeout)
	default:
		return nil, fmt.Errorf("unknown transport: %s", transport.Mode)
	}
}

// doqExchange sends a DNS message via DNS-over-QUIC (RFC 9250). Each query
// runs on a fresh bidirectional stream of a fresh QUIC connection; the
// payload is RFC 1035 wire format prefixed with its 2-byte length (same
// framing as DNS-over-TCP). ALPN must be "doq" per RFC 9250 §4.1.1.
//
// RFC 9250 strongly recommends that the DNS message ID be zero (since QUIC
// already provides stream multiplexing), but we leave that to the caller —
// modern resolvers tolerate a non-zero ID.
func doqExchange(msg *dns.Msg, server string, timeout time.Duration) (*dns.Msg, error) {
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(raw)))
	copy(framed[2:], raw)

	host, _, _ := net.SplitHostPort(server)
	tlsConf := &tls.Config{
		ServerName: host,
		NextProtos: []string{"doq", "doq-i03", "doq-i02", "doq-i00"},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, server, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("doq dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq stream: %w", err)
	}
	_ = stream.SetDeadline(time.Now().Add(timeout))

	if _, err := stream.Write(framed); err != nil {
		return nil, fmt.Errorf("doq write: %w", err)
	}
	// Close the write side; some servers wait for it before responding.
	_ = stream.Close()

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("doq read length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, fmt.Errorf("doq read body: %w", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("doq unpack: %w", err)
	}
	return out, nil
}

// queryNSID issues an A query for `host` with an EDNS0 NSID option set and
// returns whichever server identifier the resolver chose to surface (per
// RFC 5001). NSID values are anycast PoP identifiers — Cloudflare returns
// codes like "fra08" (Frankfurt PoP); Google returns numeric server IDs;
// Quad9 returns "res700.fra.rrdns.pch.net". Empty string when the resolver
// doesn't support NSID.
func queryNSID(host string, transport *dnsTransport, timeout time.Duration) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	// Add an OPT record carrying the NSID request (EDNS0NSID = 3).
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	m.Extra = append(m.Extra, opt)

	r, err := dnsExchange(m, transport, timeout)
	if err != nil || r == nil {
		return ""
	}
	// Walk response Extra for an OPT record carrying NSID.
	for _, rr := range r.Extra {
		o, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, optEntry := range o.Option {
			if n, ok := optEntry.(*dns.EDNS0_NSID); ok && n.Nsid != "" {
				return decodeNSID(n.Nsid)
			}
		}
	}
	return ""
}

// decodeNSID renders the NSID hex blob as ASCII when fully printable, hex
// otherwise. miekg/dns's EDNS0_NSID.Nsid is the hex-encoded server ID; many
// operators set it to a human-readable PoP code, but a few use opaque bytes.
func decodeNSID(hexStr string) string {
	if len(hexStr) == 0 || len(hexStr)%2 != 0 {
		return hexStr
	}
	buf := make([]byte, len(hexStr)/2)
	for i := 0; i < len(buf); i++ {
		hi, ok1 := hexNibble(hexStr[2*i])
		lo, ok2 := hexNibble(hexStr[2*i+1])
		if !ok1 || !ok2 {
			return hexStr
		}
		buf[i] = hi<<4 | lo
	}
	for _, c := range buf {
		if c < 32 || c >= 127 {
			return hexStr // not all printable — surface raw hex
		}
	}
	return string(buf)
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// queryDNS sends a DNS query for the given record type via the configured
// transport and returns the answer records. EDNS0 with a 4 KiB UDP buffer
// is negotiated so multi-record responses don't truncate; if the TC bit
// still comes back (response > 4 KiB or no EDNS), we retry over TCP.
func queryDNS(host string, qtype uint16, transport *dnsTransport, timeout time.Duration) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	r, err := dnsExchange(m, transport, timeout)
	if err != nil {
		return nil, err
	}
	// If the response was truncated, retry over TCP. miekg/dns doesn't do
	// this automatically; Go's net.Resolver does it but we use miekg directly.
	if r.Truncated && (transport == nil || transport.Mode == "udp") {
		tcpTransport := &dnsTransport{Mode: "tcp"}
		if transport != nil {
			tcpTransport.Server = transport.Server
		} else {
			tcpTransport.Server = "1.1.1.1:53"
		}
		if r2, err2 := dnsExchange(m, tcpTransport, timeout); err2 == nil {
			r = r2
		}
	}
	// Treat NXDOMAIN as "no records" rather than a hard error.
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	return r.Answer, nil
}

// dohExchange sends a DNS message via DNS-over-HTTPS (RFC 8484) using POST
// with the application/dns-message content type.
func dohExchange(msg *dns.Msg, endpoint string, timeout time.Duration) (*dns.Msg, error) {
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: HTTP %d", resp.StatusCode)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveViaTransport sends A and AAAA queries concurrently via the given
// transport and returns the combined IP list. Used as the main A/AAAA path
// when --dns is set to something other than "system".
func resolveViaTransport(host string, transport *dnsTransport, timeout time.Duration) ([]net.IP, error) {
	var ips []net.IP
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		wg.Add(1)
		go func(qtype uint16) {
			defer wg.Done()
			rrs, err := queryDNS(host, qtype, transport, timeout)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, r := range rrs {
				switch v := r.(type) {
				case *dns.A:
					ips = append(ips, v.A)
				case *dns.AAAA:
					ips = append(ips, v.AAAA)
				}
			}
		}(qt)
	}
	wg.Wait()

	if len(ips) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return ips, nil
}
