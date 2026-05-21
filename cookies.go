package main

import (
	"fmt"
	"strings"
)

// Cookie security audit — inspects Set-Cookie response headers and grades
// each cookie per RFC 6265bis. No CLI competitor does this systematically:
// curl/httpie just dump Set-Cookie raw; securityheaders.com flags CSP but
// not cookies; nmap doesn't touch HTTP-layer state. This is netdoc's
// second clean differentiator after security-header grading.

// cookieAudit summarises one Set-Cookie response header.
type cookieAudit struct {
	Name       string   `json:"name"`
	Secure     bool     `json:"secure"`
	HttpOnly   bool     `json:"http_only"`
	SameSite   string   `json:"same_site,omitempty"`  // "Strict" | "Lax" | "None" | ""
	HasPrefix  string   `json:"prefix,omitempty"`     // "__Host-" | "__Secure-" | ""
	Issues     []string `json:"issues,omitempty"`     // human-friendly findings
	Pass       bool     `json:"pass"`
}

// auditCookies parses every Set-Cookie response header from the trace and
// grades each one. Empty input → empty output (skip).
func auditCookies(setCookieHeaders []string) []cookieAudit {
	var out []cookieAudit
	for _, line := range setCookieHeaders {
		c := parseSetCookie(line)
		if c.Name == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// parseSetCookie inspects one Set-Cookie value and returns the audit result.
// Hand-parsed rather than using net/http.ReadSetCookies — we want each cookie
// graded individually with its own findings, and net/http's API doesn't
// surface prefix-conformance checks.
func parseSetCookie(raw string) cookieAudit {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return cookieAudit{}
	}
	nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nv) < 1 || nv[0] == "" {
		return cookieAudit{}
	}
	c := cookieAudit{Name: nv[0]}

	// Detect __Host- / __Secure- prefixes (RFC 6265bis §4.1.3.1, §4.1.3.2).
	switch {
	case strings.HasPrefix(c.Name, "__Host-"):
		c.HasPrefix = "__Host-"
	case strings.HasPrefix(c.Name, "__Secure-"):
		c.HasPrefix = "__Secure-"
	}

	hasDomain := false
	pathRoot := false
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		key := attr
		val := ""
		if i := strings.IndexByte(attr, '='); i >= 0 {
			key = strings.TrimSpace(attr[:i])
			val = strings.TrimSpace(attr[i+1:])
		}
		switch strings.ToLower(key) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HttpOnly = true
		case "samesite":
			c.SameSite = val
		case "domain":
			hasDomain = true
		case "path":
			if val == "/" {
				pathRoot = true
			}
		}
	}

	// Grade against the rules in RFC 6265bis + browser-enforced norms.
	if !c.Secure {
		c.Issues = append(c.Issues, "no Secure")
	}
	if !c.HttpOnly {
		c.Issues = append(c.Issues, "no HttpOnly")
	}
	switch strings.ToLower(c.SameSite) {
	case "":
		c.Issues = append(c.Issues, "no SameSite")
	case "none":
		if !c.Secure {
			c.Issues = append(c.Issues, "SameSite=None without Secure (browsers will reject)")
		}
	}
	// __Host- requires Secure, no Domain, Path=/
	if c.HasPrefix == "__Host-" {
		if !c.Secure {
			c.Issues = append(c.Issues, "__Host- prefix requires Secure")
		}
		if hasDomain {
			c.Issues = append(c.Issues, "__Host- prefix forbids Domain attribute")
		}
		if !pathRoot {
			c.Issues = append(c.Issues, "__Host- prefix requires Path=/")
		}
	}
	// __Secure- requires Secure
	if c.HasPrefix == "__Secure-" && !c.Secure {
		c.Issues = append(c.Issues, "__Secure- prefix requires Secure")
	}

	c.Pass = len(c.Issues) == 0
	return c
}

// cookieSummary builds a compact one-line description of the cookie audit
// suitable for the Security check's hint area. Examples:
//   "3 cookies: 2 pass · 1 missing Secure"
//   "1 cookie: missing Secure, HttpOnly, SameSite"
//   "no cookies set"
func cookieSummary(audits []cookieAudit) string {
	if len(audits) == 0 {
		return ""
	}
	pass := 0
	for _, a := range audits {
		if a.Pass {
			pass++
		}
	}
	if pass == len(audits) {
		return fmt.Sprintf("cookies: %d/%d secure", pass, len(audits))
	}
	return fmt.Sprintf("cookies: %d/%d secure · %d need work", pass, len(audits), len(audits)-pass)
}
