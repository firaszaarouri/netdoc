package main

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS Cookies (RFC 7873) round-trip probe. DNS Cookies are an EDNS option
// (code 10) that provide a lightweight anti-spoofing mechanism: the client
// sends an 8-byte client_cookie; the server responds with a 16-byte
// server_cookie that subsequent queries must echo. Servers without DNS
// Cookie support omit the option in their response.
//
// netdoc surfaces:
//   - Server supports DNS Cookies? (server_cookie returned)
//   - Server cookie value (16 bytes hex)
//
// Reference: RFC 7873.

// dnsCookieResult records the verdict.
type dnsCookieResult struct {
	Attempted    bool   `json:"attempted"`
	Supported    bool   `json:"supported"`
	ClientCookie string `json:"client_cookie,omitempty"` // 8 bytes hex we sent
	ServerCookie string `json:"server_cookie,omitempty"` // 8-32 bytes hex returned
	ErrorBadCookie bool `json:"error_bad_cookie,omitempty"` // BADCOOKIE rcode (23)
}

// probeDNSCookies sends an A query with a randomly-generated client_cookie
// EDNS option and parses the server's reply for a server_cookie.
func probeDNSCookies(host string, transport *dnsTransport, timeout time.Duration) dnsCookieResult {
	out := dnsCookieResult{Attempted: true}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	clientCookie := make([]byte, 8)
	_, _ = rand.Read(clientCookie)
	out.ClientCookie = hex.EncodeToString(clientCookie)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
	}
	cookieOpt := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: hex.EncodeToString(clientCookie),
	}
	opt.Option = append(opt.Option, cookieOpt)
	m.Extra = append(m.Extra, opt)

	resp, err := dnsExchange(m, transport, timeout)
	if err != nil || resp == nil {
		return out
	}
	// BADCOOKIE (rcode 23) means server supports DNS Cookies but our
	// client_cookie was rejected — typically because we didn't echo back
	// a server_cookie from a prior round-trip. The presence of BADCOOKIE
	// itself proves support.
	if resp.Rcode == 23 {
		out.ErrorBadCookie = true
		out.Supported = true
		return out
	}
	for _, rr := range resp.Extra {
		o, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, e := range o.Option {
			c, ok := e.(*dns.EDNS0_COOKIE)
			if !ok {
				continue
			}
			full := c.Cookie
			// Per RFC 7873, the cookie field is client_cookie (8) ||
			// server_cookie (8-32). Our client cookie hex is 16 chars; the
			// rest is the server cookie.
			if len(full) > 16 {
				out.ServerCookie = full[16:]
				out.Supported = true
			}
		}
	}
	return out
}

// dnsCookiesHeadline returns "DNS Cookies: <8-char hex>…" for the hint.
func dnsCookiesHeadline(r dnsCookieResult) string {
	if !r.Attempted || !r.Supported {
		return ""
	}
	if r.ServerCookie != "" {
		c := r.ServerCookie
		if len(c) > 8 {
			c = c[:8] + "…"
		}
		return "DNS Cookies: " + c
	}
	if r.ErrorBadCookie {
		return "DNS Cookies: supported (BADCOOKIE)"
	}
	return strings.Repeat("", 0) // unreachable
}
