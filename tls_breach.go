package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// BREACH (Browser Reconnaissance and Exfiltration via Adaptive
// Compression of Hypertext) detection. Mirrors testssl.sh's `-B / --breach`
// flag.
//
// CVE-2013-3587. BREACH is the HTTP-layer equivalent of CRIME:
//
//   - When the server returns a compressed response (Content-Encoding:
//     gzip or deflate) AND the response body reflects attacker-controlled
//     input (URL query, form field, header), an attacker who can observe
//     the encrypted response length over many requests can recover secret
//     tokens (CSRF, session) byte-by-byte via chosen-plaintext compression.
//
// Detection technique here matches testssl.sh's heuristic exactly:
//
//   Send an HTTP GET with `Accept-Encoding: gzip, deflate, compress`
//   and check the response's Content-Encoding header. If the server
//   responds with gzip / deflate, mark as POTENTIALLY VULNERABLE — the
//   attack requires the second precondition (reflected input) which
//   can't be tested in a single probe without targeted payloads.
//
// We're explicit about the limitation: "potentially vulnerable" means
// "preconditions met; targeted testing required to confirm." Unlike
// CRIME (TLS-layer compression) which is rare in 2026, BREACH is still
// common because HTTP gzip is normal performance hygiene — the fix is
// at the application layer (don't reflect secrets next to attacker input).

type breachResult struct {
	Probed             bool   `json:"probed"`
	CompressionEnabled bool   `json:"compression_enabled"`
	Encoding           string `json:"encoding,omitempty"`
	Vary               string `json:"vary,omitempty"`
	Note               string `json:"note,omitempty"`
}

// probeBREACH sends one HTTPS HEAD request advertising compression and
// inspects the response. We use HEAD so we don't pull bytes, and we
// honor a custom TLS dialer for the starttls case via the diagnosis
// context (this probe only fires when the target is HTTP-capable,
// not for raw STARTTLS probes).
func probeBREACH(host string, port int, timeout time.Duration) breachResult {
	out := breachResult{Probed: true}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}

	// HEAD via a custom transport — we want the server to think we
	// accept compression even though we discard the body.
	transport := &http.Transport{
		TLSHandshakeTimeout: timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		},
		// CRITICAL: disable Go's automatic gzip handling so the response
		// header preserves Content-Encoding for our inspection. Without
		// this Go silently transparently-decompresses.
		DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	scheme := "https"
	if port == 80 || port == 8080 {
		scheme = "http"
	}
	addr := host
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		addr = host + ":" + itoa(port)
	}
	req, err := http.NewRequest(http.MethodHead, scheme+"://"+addr+"/", nil)
	if err != nil {
		out.Note = "request build failed: " + tidyErr(err)
		return out
	}
	req.Header.Set("User-Agent", "netdoc/"+version)
	// Advertise every compression method commonly supported. Servers
	// that gzip will say so in Content-Encoding.
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, compress")

	resp, err := client.Do(req)
	if err != nil {
		out.Note = "HEAD failed: " + tidyErr(err)
		return out
	}
	defer resp.Body.Close()

	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	vary := resp.Header.Get("Vary")
	out.Encoding = enc
	out.Vary = vary

	if enc == "" {
		out.CompressionEnabled = false
		out.Note = "no Content-Encoding — BREACH preconditions not met"
		return out
	}
	if enc == "gzip" || enc == "deflate" || enc == "br" || enc == "compress" {
		out.CompressionEnabled = true
		out.Note = "Content-Encoding: " + enc + " — vulnerable IF response reflects attacker-controlled input. Mitigations: don't reflect secrets in compressed responses; use CSRF tokens that don't appear in HTML body; disable compression for sensitive endpoints."
		// A Vary: Accept-Encoding header indicates caching awareness;
		// note for completeness.
		if vary != "" && strings.Contains(strings.ToLower(vary), "accept-encoding") {
			out.Note += " (Vary: Accept-Encoding present — at least cache-aware)"
		}
		return out
	}
	out.CompressionEnabled = false
	out.Note = "unknown Content-Encoding " + enc
	return out
}

// breachHeadline returns "BREACH: gzip enabled (reflection-dependent)"
// when the precondition is met, empty otherwise.
func breachHeadline(b breachResult) string {
	if !b.Probed || !b.CompressionEnabled {
		return ""
	}
	return "BREACH: " + b.Encoding + " enabled (reflection-dependent)"
}
