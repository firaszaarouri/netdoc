package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// checkHTTP synthesises the HTTP check result from the single httptrace
// transaction captured by runTrace. There is no separate request issued
// here — the timings shown for HTTP are exactly the timings in the chart.
func (d *diagnosis) checkHTTP() Check {
	c := Check{Name: "HTTP"}
	if !d.resolved {
		c.Status = StatusSkip
		c.Summary = "skipped — DNS did not resolve"
		return c
	}
	if d.trace == nil {
		c.Status = StatusFail
		c.Summary = "no HTTP transaction was run"
		return c
	}
	t := d.trace
	if t.err != nil {
		c.Status = StatusFail
		c.Summary = "request failed: " + t.HTTPError
		c.Detail = map[string]any{"error": t.HTTPError}
		return c
	}

	c.Detail = map[string]any{
		"status":          t.HTTPStatus,
		"proto":           t.HTTPProto,
		"ttfb_ms":         t.TCPPhase + t.TLSPhase + t.ServerPhase,
		"total_ms":        t.TotalPhase,
		"redirects":       t.HTTPRedirects,
		"length":          t.ContentLength,
		"hsts":            t.HSTS,
		"alt_svc":         t.AltSvc,
		"body_bytes":      t.BodyBytes,
		"body_ms":         t.BodyMs,
		"throughput_kbps": t.ThroughputKBps,
	}
	if len(t.RedirectChain) > 0 {
		c.Detail["redirect_chain"] = t.RedirectChain
	}
	c.Millis = t.ServerPhase

	redirectText := "no redirects"
	if t.HTTPRedirects == 1 {
		redirectText = "1 redirect"
	} else if t.HTTPRedirects > 1 {
		redirectText = fmt.Sprintf("%d redirects", t.HTTPRedirects)
	}
	line1 := []string{redirectText}
	if t.HTTPServer != "" {
		line1 = append(line1, "server: "+t.HTTPServer)
	}
	c.Hint = strings.Join(line1, "  ·  ")

	// When there are redirects, render the chain on its own lines under the
	// summary so the reader sees the actual hop URLs (curl-style). The chain
	// stored in t.RedirectChain already includes the originating URL.
	if len(t.RedirectChain) > 1 {
		var chainLines []string
		for i := 0; i < len(t.RedirectChain)-1; i++ {
			from := t.RedirectChain[i]
			to := t.RedirectChain[i+1]
			chainLines = append(chainLines, fmt.Sprintf("→ %s  →  %s",
				truncate(from, 38), truncate(to, 38)))
		}
		c.Hint += "\n" + strings.Join(chainLines, "\n")
	}

	// Final hint line: security headers, HTTP/3 advertisement, body throughput.
	// When Alt-Svc advertises h3, run a real QUIC handshake to confirm the
	// server actually speaks HTTP/3 — Alt-Svc alone only proves intent, not
	// reachability (UDP/443 may be blocked, the QUIC stack may misbehave).
	advertisesH3 := strings.Contains(t.AltSvc, "h3=") || strings.Contains(t.AltSvc, "h3-")
	var h3 http3Result
	if advertisesH3 {
		h3 = probeHTTP3(d.host, d.port, d.timeout)
		c.Detail["http3"] = h3
	}

	// OPTIONS sweep — enumerate HTTP methods + flag risky verbs (TRACE
	// enables XST, CONNECT is proxy, PUT/DELETE often unintended on static
	// servers). nmap's http-methods NSE equivalent.
	opts := probeHTTPOptions(d.scheme, d.host, d.port, d.timeout)
	if len(opts.Allow) > 0 || len(opts.Public) > 0 || opts.TRACEEnabled || opts.WebDAV {
		c.Detail["http_options"] = opts
	}

	// CORS misconfig probe — Origin reflection / wildcard+credentials.
	cors := probeCORS(d.scheme, d.host, d.port, d.timeout)
	if cors.Probed {
		c.Detail["cors"] = cors
	}

	// Server-Timing parse — render the per-component timing breakdown.
	serverTiming := parseServerTiming(t.Headers.Get("Server-Timing"))
	if len(serverTiming) > 0 {
		c.Detail["server_timing"] = serverTiming
	}

	// SRI + mixed-content scan via x/net/html. Runs only when the trace
	// captured an HTML body (Content-Type contained "html").
	var htmlScan htmlScanResult
	if t.BodyHead != nil {
		htmlScan = scanHTML(t.BodyHead, d.scheme, d.host)
		if htmlScan.ExternalScripts > 0 || htmlScan.ExternalStyles > 0 ||
			len(htmlScan.MixedContent) > 0 || len(htmlScan.InsecureForms) > 0 ||
			len(htmlScan.IframesUntrusted) > 0 {
			c.Detail["html_scan"] = htmlScan
		}
	}

	var line2 []string
	if t.HSTS != "" {
		line2 = append(line2, "HSTS")
	}
	switch {
	case h3.Supported:
		line2 = append(line2, fmt.Sprintf("HTTP/3 confirmed (%.0fms handshake)", h3.HandshakeMS))
	case advertisesH3 && h3.Error != "":
		line2 = append(line2, "HTTP/3 advertised but handshake failed")
	case advertisesH3:
		line2 = append(line2, "HTTP/3 advertised")
	}
	switch {
	case t.BodyBytes >= 1024 && t.ThroughputKBps > 0:
		line2 = append(line2, fmt.Sprintf("%.1f KB at %.0f KB/s",
			float64(t.BodyBytes)/1024.0, t.ThroughputKBps))
	case t.BodyBytes > 0:
		line2 = append(line2, fmt.Sprintf("%d B body", t.BodyBytes))
	}
	if t.HTMLTitle != "" {
		line2 = append(line2, "“"+t.HTMLTitle+"”")
	}
	if len(opts.Allow) > 0 {
		line2 = append(line2, "Allow: "+strings.Join(opts.Allow, ","))
	}
	if opts.TRACEEnabled {
		line2 = append(line2, "TRACE enabled (XST)")
	}
	if opts.WebDAV {
		line2 = append(line2, "WebDAV")
	}
	if len(opts.Risky) > 0 && !opts.TRACEEnabled {
		line2 = append(line2, "risky verbs: "+strings.Join(opts.Risky, ","))
	}
	if v := serverTimingHeadline(serverTiming); v != "" {
		line2 = append(line2, v)
	}
	if v := corsHeadline(cors); v != "" {
		line2 = append(line2, v)
	}
	if v := htmlScanHeadline(htmlScan); v != "" {
		line2 = append(line2, v)
	}
	if t.JSONValid && strings.Contains(t.ContentType, "json") {
		line2 = append(line2, "JSON body parses")
	}
	// Time-skew check — compare the server's Date header to local clock.
	// Large skew (>5 min) breaks JWT validation, OCSP nonces, TOTP, etc.
	if dateHdr := t.Headers.Get("Date"); dateHdr != "" {
		if serverTime, err := time.Parse(time.RFC1123, dateHdr); err == nil {
			skew := time.Since(serverTime)
			if skew < 0 {
				skew = -skew
			}
			if skew > 5*time.Minute {
				line2 = append(line2, fmt.Sprintf("server clock skew %s", dur(skew)))
			}
		}
	}
	if len(line2) > 0 {
		c.Hint += "\n" + strings.Join(line2, "  ·  ")
	}

	statusText := fmt.Sprintf("%s %d %s", t.HTTPProto, t.HTTPStatus, http.StatusText(t.HTTPStatus))
	serverDur := time.Duration(t.ServerPhase * float64(time.Millisecond))
	switch {
	case t.HTTPStatus >= 500:
		c.Status = StatusFail
		c.Summary = statusText
	case t.HTTPStatus >= 400:
		c.Status = StatusWarn
		c.Summary = statusText
	case t.ServerPhase > 1000:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%s — slow server response, %s", statusText, dur(serverDur))
	default:
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("%s — server responded in %s", statusText, dur(serverDur))
	}
	return c
}
