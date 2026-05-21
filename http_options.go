package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTP OPTIONS sweep — the nmap `http-methods` NSE equivalent. Sends an
// OPTIONS request and parses the server's Allow header to enumerate which
// HTTP verbs the server accepts. Flags risky verbs (TRACE, CONNECT, PUT,
// DELETE, WebDAV verbs) as separate posture signals.
//
// Reference: RFC 9110 §9.3.7 (OPTIONS), §9.3.8 (TRACE).
// XST background: https://owasp.org/www-community/attacks/Cross_Site_Tracing

// httpOptionsResult is what we learned from the OPTIONS sweep.
type httpOptionsResult struct {
	Allow        []string `json:"allow,omitempty"`
	Public       []string `json:"public,omitempty"`
	Risky        []string `json:"risky,omitempty"`         // methods that warrant attention
	WebDAV       bool     `json:"webdav,omitempty"`        // PROPFIND/etc. present → WebDAV
	TRACEEnabled bool     `json:"trace_enabled,omitempty"` // XST risk
}

// probeHTTPOptions issues an OPTIONS request against the target URL and parses
// the Allow / Public response headers. Times out at the diagnosis deadline.
func probeHTTPOptions(scheme, host string, port int, timeout time.Duration) httpOptionsResult {
	var res httpOptionsResult
	url := scheme + "://" + host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		url += ":" + itoa(port)
	}
	url += "/"

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodOptions, url, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", "netdoc/2.9")
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	// Drain the body so the underlying conn can be reused if keep-alive were on.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if allow := resp.Header.Get("Allow"); allow != "" {
		res.Allow = splitMethods(allow)
	}
	if public := resp.Header.Get("Public"); public != "" {
		res.Public = splitMethods(public)
	}
	// Fold Public into Allow if Allow is missing.
	if len(res.Allow) == 0 && len(res.Public) > 0 {
		res.Allow = res.Public
	}

	allMethods := dedupeMethods(append(append([]string{}, res.Allow...), res.Public...))
	for _, m := range allMethods {
		switch m {
		case "TRACE":
			res.TRACEEnabled = true
			res.Risky = appendUnique(res.Risky, "TRACE")
		case "CONNECT":
			res.Risky = appendUnique(res.Risky, "CONNECT")
		case "PUT":
			res.Risky = appendUnique(res.Risky, "PUT")
		case "DELETE":
			res.Risky = appendUnique(res.Risky, "DELETE")
		case "PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK":
			res.WebDAV = true
		}
	}
	return res
}

// splitMethods normalises a comma-separated method list to uppercase tokens.
func splitMethods(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dedupeMethods returns a deduplicated copy preserving order.
func dedupeMethods(ms []string) []string {
	seen := map[string]bool{}
	out := ms[:0:0]
	for _, m := range ms {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
