package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// TraceResult holds the per-phase timings and HTTP-level result of a single
// transaction against the target. The phases are captured via net/http/httptrace
// so they never double-count one another — the chart, the HTTP check and any
// future per-phase analysis all read from this single source of truth.
type TraceResult struct {
	// Phase timings, milliseconds.
	DNSPhase    float64 `json:"dns_phase_ms,omitempty"`
	TCPPhase    float64 `json:"tcp_phase_ms,omitempty"`
	TLSPhase    float64 `json:"tls_phase_ms,omitempty"`
	ServerPhase float64 `json:"server_phase_ms,omitempty"`
	TotalPhase  float64 `json:"total_phase_ms,omitempty"`

	// HTTP-level result.
	HTTPStatus     int      `json:"http_status,omitempty"`
	HTTPProto      string   `json:"http_proto,omitempty"`
	HTTPRedirects  int      `json:"http_redirects,omitempty"`
	HTTPServer     string   `json:"http_server,omitempty"`
	HTTPError      string   `json:"http_error,omitempty"`
	ContentLength  int64    `json:"content_length,omitempty"`
	RedirectChain  []string `json:"redirect_chain,omitempty"`
	HSTS           string   `json:"hsts,omitempty"`
	AltSvc         string   `json:"alt_svc,omitempty"`
	BodyBytes      int64    `json:"body_bytes,omitempty"`
	BodyMs         float64  `json:"body_ms,omitempty"`
	ThroughputKBps float64  `json:"throughput_kbps,omitempty"`

	// ContentType and BodyPreview surface what the server actually sent.
	// HTMLTitle is the <title> when the response is HTML; JSONValid is set
	// when the first ~2KB parses as JSON. Together these give a one-glance
	// sanity check that the response is what the user expected.
	ContentType string `json:"content_type,omitempty"`
	HTMLTitle   string `json:"html_title,omitempty"`
	JSONValid   bool   `json:"json_valid,omitempty"`

	// BodyHead carries up to 64 KB of HTML body for the SRI / mixed-content
	// scanner. Populated only when the response Content-Type indicates HTML;
	// nil otherwise. Cleared from JSON output via json:"-".
	BodyHead []byte `json:"-"`

	// Headers carries every response header from the final response. The
	// Security check reads this to grade headers like CSP, X-Frame-Options,
	// COOP/COEP/CORP, Permissions-Policy, etc. It's marshalled into JSON as
	// a flat object so consumers can inspect anything we don't grade.
	Headers http.Header `json:"headers,omitempty"`

	// err carries the request error for in-process consumers. Unexported so
	// it does not appear in JSON; HTTPError above carries the serialised form.
	err error
}

// runTrace performs one HTTP GET to the target and records every phase
// boundary (DNS / TCP / TLS / server / total) via httptrace. The result is
// stored on d.trace and also returned. Returns nil if DNS hasn't resolved yet.
func (d *diagnosis) runTrace() *TraceResult {
	if !d.resolved {
		return nil
	}

	host := d.host
	if (d.scheme == "https" && d.port != 443) || (d.scheme == "http" && d.port != 80) {
		host = fmt.Sprintf("%s:%d", d.host, d.port)
	}
	target := fmt.Sprintf("%s://%s", d.scheme, host)

	var dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, firstByte time.Time

	// Only the first occurrence of each event is recorded — redirects open new
	// connections that would otherwise overwrite the original phase timings.
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			if dnsStart.IsZero() {
				dnsStart = time.Now()
			}
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			if dnsDone.IsZero() {
				dnsDone = time.Now()
			}
		},
		ConnectStart: func(string, string) {
			if connStart.IsZero() {
				connStart = time.Now()
			}
		},
		ConnectDone: func(string, string, error) {
			if connDone.IsZero() {
				connDone = time.Now()
			}
		},
		TLSHandshakeStart: func() {
			if tlsStart.IsZero() {
				tlsStart = time.Now()
			}
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if tlsDone.IsZero() {
				tlsDone = time.Now()
			}
		},
		GotFirstResponseByte: func() {
			if firstByte.IsZero() {
				firstByte = time.Now()
			}
		},
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t := &TraceResult{err: err, HTTPError: tidyErr(err)}
		d.trace = t
		return t
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))
	req.Header.Set("User-Agent", "netdoc/"+version)

	redirects := 0
	var chain []string
	client := &http.Client{
		Timeout: d.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(chain) == 0 && len(via) > 0 {
				chain = append(chain, via[0].URL.String())
			}
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	start := time.Now()
	resp, reqErr := client.Do(req)
	end := time.Now()

	t := &TraceResult{HTTPRedirects: redirects}
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		t.DNSPhase = ms(dnsDone.Sub(dnsStart))
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		t.TCPPhase = ms(connDone.Sub(connStart))
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		t.TLSPhase = ms(tlsDone.Sub(tlsStart))
	}
	if !firstByte.IsZero() {
		var lastNet time.Time
		switch {
		case !tlsDone.IsZero():
			lastNet = tlsDone
		case !connDone.IsZero():
			lastNet = connDone
		}
		if !lastNet.IsZero() {
			t.ServerPhase = ms(firstByte.Sub(lastNet))
		}
	}
	t.TotalPhase = ms(end.Sub(start))

	if reqErr != nil {
		t.err = reqErr
		msg := tidyErr(reqErr)
		if ue, ok := reqErr.(*url.Error); ok {
			msg = tidyErr(ue.Err)
		}
		t.HTTPError = msg
		d.trace = t
		return t
	}
	defer resp.Body.Close()
	bodyStart := time.Now()
	// Peek the first chunk for content inspection. For HTML responses bump
	// the peek to 64 KB so we capture the entire <head> + a slice of body,
	// enough for the SRI / mixed-content scanner to find every <script src>
	// / <link href> in the head. For non-HTML stay at 2 KB.
	peekSize := 2048
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "html") {
		peekSize = 64 * 1024
	}
	peekBuf := make([]byte, peekSize)
	peekN, _ := io.ReadFull(resp.Body, peekBuf)
	peekBuf = peekBuf[:peekN]
	restN, _ := io.Copy(io.Discard, resp.Body)
	n := int64(peekN) + restN
	bodyMs := ms(time.Since(bodyStart))

	t.HTTPStatus = resp.StatusCode
	t.HTTPProto = resp.Proto
	t.HTTPServer = resp.Header.Get("Server")
	t.HSTS = resp.Header.Get("Strict-Transport-Security")
	t.AltSvc = resp.Header.Get("Alt-Svc")
	t.ContentLength = resp.ContentLength
	t.BodyBytes = n
	t.BodyMs = bodyMs
	if bodyMs > 0 && n > 0 {
		t.ThroughputKBps = float64(n) / 1024.0 / (bodyMs / 1000.0)
	}
	if len(chain) > 0 {
		t.RedirectChain = chain
	}
	t.Headers = resp.Header.Clone()
	t.ContentType = resp.Header.Get("Content-Type")
	if title := extractHTMLTitle(peekBuf); title != "" {
		t.HTMLTitle = title
	}
	if looksLikeJSON(peekBuf) {
		t.JSONValid = true
	}
	// Stash the peek so the HTTP check can run the HTML SRI / mixed-content
	// scanner without re-fetching. Only kept for HTML responses to bound
	// per-request memory; cleared after the HTTP check consumes it.
	if strings.Contains(ct, "html") {
		t.BodyHead = append([]byte(nil), peekBuf...)
	}

	d.trace = t
	return t
}

// extractHTMLTitle returns the text inside the first <title>…</title> tag
// found in the byte slice (case-insensitive on the tag). Empty when there
// isn't a title or the body isn't HTML.
func extractHTMLTitle(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	lower := strings.ToLower(string(b))
	open := strings.Index(lower, "<title")
	if open < 0 {
		return ""
	}
	// Skip to the closing '>' of the open tag (could carry attributes).
	gt := strings.IndexByte(lower[open:], '>')
	if gt < 0 {
		return ""
	}
	start := open + gt + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(string(b[start : start+end]))
	// Collapse whitespace
	title = strings.Join(strings.Fields(title), " ")
	return truncate(title, 64)
}

// looksLikeJSON reports whether the byte slice begins with a JSON document
// after skipping leading whitespace. We don't try to validate completeness
// (we only have a peek of the body); this just tells us "the server's
// content-type claim and the body shape agree".
func looksLikeJSON(b []byte) bool {
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		return c == '{' || c == '['
	}
	return false
}
