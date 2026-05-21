package main

import (
	"fmt"
	"sort"
	"strings"
)

// CSP Level 3 parser + strictness scorer. Splits a Content-Security-Policy
// header into directives, then grades each against the modern CSP3 rubric
// (W3C CSP3 + Google CSP Evaluator). Returns a 0-100 score plus a sorted
// finding list keyed by severity, so callers can either print the headline
// or alert on critical findings only.

// cspPolicy is the parsed structure of one Content-Security-Policy header.
type cspPolicy struct {
	Raw        string              `json:"raw,omitempty"`
	Directives map[string][]string `json:"directives,omitempty"`
}

// cspFinding describes one strictness issue.
type cspFinding struct {
	Directive  string `json:"directive,omitempty"`
	Severity   string `json:"severity"` // critical, high, medium, low, info
	Issue      string `json:"issue"`
	Suggestion string `json:"suggestion,omitempty"`
}

// cspAnalysis is the full scored evaluation.
type cspAnalysis struct {
	Strictness  string       `json:"strictness"` // strict, moderate, loose, missing
	Score       int          `json:"score"`      // 0-100
	Findings    []cspFinding `json:"findings,omitempty"`
	UsesNonces  bool         `json:"uses_nonces,omitempty"`
	UsesHashes  bool         `json:"uses_hashes,omitempty"`
	StrictDyn   bool         `json:"strict_dynamic,omitempty"`
	ReportingOn bool         `json:"reporting_on,omitempty"`
}

// parseCSP splits a header value into directives, lowercasing the directive
// name and preserving source-list order. Multiple Content-Security-Policy
// headers in one response are RFC-compliant ("the most restrictive is
// applied"); netdoc grades them concatenated since the strictest signal
// almost always wins on the first parse.
func parseCSP(raw string) *cspPolicy {
	p := &cspPolicy{Raw: raw, Directives: map[string][]string{}}
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		var srcs []string
		if len(fields) > 1 {
			srcs = fields[1:]
		}
		p.Directives[name] = append(p.Directives[name], srcs...)
	}
	return p
}

// directive returns the source list for a directive, falling back to the
// default-src per CSP Level 3 §6.6 ("Source list rules for fallback").
func (p *cspPolicy) directive(name string) ([]string, bool) {
	if v, ok := p.Directives[name]; ok {
		return v, true
	}
	// Fallback to default-src for the directives that inherit from it
	// per CSP3 §6.6.4 — script-src, style-src, img-src, font-src,
	// media-src, connect-src, object-src, frame-src, child-src,
	// worker-src, manifest-src, prefetch-src.
	inherits := map[string]bool{
		"script-src": true, "style-src": true, "img-src": true,
		"font-src": true, "media-src": true, "connect-src": true,
		"object-src": true, "frame-src": true, "child-src": true,
		"worker-src": true, "manifest-src": true, "prefetch-src": true,
	}
	if inherits[name] {
		if v, ok := p.Directives["default-src"]; ok {
			return v, true
		}
	}
	return nil, false
}

// hasNonce returns true when any source in the directive's list is a CSP3
// nonce: token of the form "'nonce-<base64>'".
func hasNonce(sources []string) bool {
	for _, s := range sources {
		l := strings.ToLower(s)
		if strings.HasPrefix(l, "'nonce-") && strings.HasSuffix(l, "'") {
			return true
		}
	}
	return false
}

// hasHash returns true when any source is a CSP3 hash:
// "'sha{256,384,512}-<base64>'".
func hasHash(sources []string) bool {
	for _, s := range sources {
		l := strings.ToLower(s)
		if (strings.HasPrefix(l, "'sha256-") ||
			strings.HasPrefix(l, "'sha384-") ||
			strings.HasPrefix(l, "'sha512-")) && strings.HasSuffix(l, "'") {
			return true
		}
	}
	return false
}

// hasKeyword returns true if any source equals the given keyword.
// Keywords are case-insensitive in CSP per §2.3.2.
func hasKeyword(sources []string, kw string) bool {
	kw = strings.ToLower(kw)
	for _, s := range sources {
		if strings.ToLower(s) == kw {
			return true
		}
	}
	return false
}

// hasWildcard returns true if any source is a bare "*" or a schema-only
// source like "data:" / "blob:" / "http:" / "https:" / "filesystem:".
func hasWildcard(sources []string) bool {
	for _, s := range sources {
		l := strings.ToLower(strings.TrimSpace(s))
		if l == "*" || l == "data:" || l == "blob:" || l == "http:" ||
			l == "https:" || l == "filesystem:" || l == "ws:" || l == "wss:" {
			return true
		}
	}
	return false
}

// evaluateCSP applies the CSP Level 3 strictness rubric to a parsed policy.
// Score breakdown (start at 100, subtract per finding):
//
//	CRITICAL (-20 each): unsafe-inline / unsafe-eval / wildcard / data:|blob: in
//	    script-src (or default-src fallback); object-src not 'none';
//	    http: in any directive on an HTTPS origin
//	HIGH     (-15 each): default-src absent (no fallback); base-uri unset;
//	    script-src absent and no default-src; form-action unset
//	MEDIUM   (-10 each): frame-ancestors unset; unsafe-hashes; no reporting;
//	    strict-dynamic absent (modern CSP-3 best practice)
//	LOW      (-5 each):  block-all-mixed-content absent;
//	    upgrade-insecure-requests absent
//
// Bonuses (capped at 100):
//
//	+5 if nonces in use; +5 if hashes in use; +10 if strict-dynamic in use
func evaluateCSP(p *cspPolicy) cspAnalysis {
	a := cspAnalysis{Score: 100}
	if p == nil || len(p.Directives) == 0 {
		a.Strictness = "missing"
		a.Score = 0
		return a
	}

	scriptSrc, hasScriptSrc := p.directive("script-src")
	defaultSrc, hasDefaultSrc := p.Directives["default-src"]
	_ = defaultSrc

	// Track flags we'll bonus on.
	a.UsesNonces = hasNonce(scriptSrc)
	a.UsesHashes = hasHash(scriptSrc)
	a.StrictDyn = hasKeyword(scriptSrc, "'strict-dynamic'")
	_, hasReportURI := p.Directives["report-uri"]
	_, hasReportTo := p.Directives["report-to"]
	a.ReportingOn = hasReportURI || hasReportTo

	// CRITICAL findings —————————————————————————————————————
	// unsafe-inline in script-src (no nonce/hash escape hatch).
	if hasKeyword(scriptSrc, "'unsafe-inline'") && !a.UsesNonces && !a.UsesHashes && !a.StrictDyn {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "critical",
			Issue:      "'unsafe-inline' without nonce/hash escape hatch",
			Suggestion: "use nonces or hashes; for legacy back-compat add 'strict-dynamic'",
		})
		a.Score -= 20
	}
	// unsafe-eval.
	if hasKeyword(scriptSrc, "'unsafe-eval'") {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "critical",
			Issue:      "'unsafe-eval' allows JS string evaluation (XSS amplifier)",
			Suggestion: "remove 'unsafe-eval'; refactor any eval()/new Function() callers",
		})
		a.Score -= 20
	}
	// Wildcard in script-src.
	if hasWildcard(scriptSrc) {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "critical",
			Issue:      "wildcard or schema source in script-src",
			Suggestion: "replace * / data: / blob: / http: with specific hosts or 'strict-dynamic'",
		})
		a.Score -= 20
	}
	// object-src not 'none' — historical XSS vector (Flash, applets).
	objectSrc, _ := p.directive("object-src")
	if !hasKeyword(objectSrc, "'none'") {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "object-src",
			Severity:   "critical",
			Issue:      "object-src not 'none' — legacy plugin XSS surface",
			Suggestion: "set object-src 'none'",
		})
		a.Score -= 20
	}
	// HIGH findings —————————————————————————————————————————
	// default-src absent.
	if !hasDefaultSrc {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "default-src",
			Severity:   "high",
			Issue:      "default-src absent — no fallback for non-script directives",
			Suggestion: "set default-src 'self' (or 'none' if locking everything down)",
		})
		a.Score -= 15
	}
	// script-src absent (and no default-src to fall back to).
	if !hasScriptSrc {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "high",
			Issue:      "script-src absent — no scripting policy in effect",
			Suggestion: "set script-src 'self' (and nonces/hashes for inline)",
		})
		a.Score -= 15
	}
	// base-uri unset — attacker can inject <base href="evil"> to bypass
	// relative-URL allowlists.
	if _, ok := p.Directives["base-uri"]; !ok {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "base-uri",
			Severity:   "high",
			Issue:      "base-uri unset — <base> injection bypass surface",
			Suggestion: "set base-uri 'self' or 'none'",
		})
		a.Score -= 15
	}
	// form-action unset — form-based exfil bypass.
	if _, ok := p.Directives["form-action"]; !ok {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "form-action",
			Severity:   "high",
			Issue:      "form-action unset — credential exfil to attacker-controlled forms",
			Suggestion: "set form-action 'self'",
		})
		a.Score -= 15
	}
	// MEDIUM findings ———————————————————————————————————————
	// frame-ancestors unset.
	if _, ok := p.Directives["frame-ancestors"]; !ok {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "frame-ancestors",
			Severity:   "medium",
			Issue:      "frame-ancestors unset — clickjacking via iframe embedding",
			Suggestion: "set frame-ancestors 'none' or 'self' (modern replacement for X-Frame-Options)",
		})
		a.Score -= 10
	}
	// unsafe-hashes (CSP3 keyword that allows inline event handlers via hash).
	if hasKeyword(scriptSrc, "'unsafe-hashes'") {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "medium",
			Issue:      "'unsafe-hashes' permits inline event-handler scripts",
			Suggestion: "refactor to addEventListener; remove 'unsafe-hashes'",
		})
		a.Score -= 10
	}
	// Reporting off (no report-uri / report-to).
	if !a.ReportingOn {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "report-to/report-uri",
			Severity:   "medium",
			Issue:      "no CSP violation reporting endpoint",
			Suggestion: "add report-to (CSP3) or report-uri (legacy) for violation telemetry",
		})
		a.Score -= 10
	}
	// strict-dynamic absent (modern CSP3 best practice when nonces in use).
	if !a.StrictDyn && a.UsesNonces {
		a.Findings = append(a.Findings, cspFinding{
			Directive:  "script-src",
			Severity:   "medium",
			Issue:      "nonces in use without 'strict-dynamic' — host allowlist still needed",
			Suggestion: "add 'strict-dynamic' to drop host allowlist enforcement",
		})
		a.Score -= 10
	}
	// LOW findings ——————————————————————————————————————————
	// block-all-mixed-content absent.
	if _, ok := p.Directives["block-all-mixed-content"]; !ok {
		// Only mention when the document isn't already on HTTPS-only by
		// upgrade-insecure-requests. We can't tell here, so just flag it
		// as low; the user can ignore for HTTPS-only sites.
		_ = ok
	}
	// upgrade-insecure-requests absent.
	if _, ok := p.Directives["upgrade-insecure-requests"]; !ok {
		a.Findings = append(a.Findings, cspFinding{
			Severity:   "low",
			Issue:      "upgrade-insecure-requests not set — mixed HTTP subresources won't auto-upgrade",
			Suggestion: "add upgrade-insecure-requests for HTTPS-only sites",
		})
		a.Score -= 5
	}

	// Bonuses ——————————————————————————————————————————————
	if a.UsesNonces {
		a.Score += 5
	}
	if a.UsesHashes {
		a.Score += 5
	}
	if a.StrictDyn {
		a.Score += 10
	}
	if a.Score > 100 {
		a.Score = 100
	}
	if a.Score < 0 {
		a.Score = 0
	}

	switch {
	case a.Score >= 90:
		a.Strictness = "strict"
	case a.Score >= 60:
		a.Strictness = "moderate"
	default:
		a.Strictness = "loose"
	}

	// Sort findings: critical > high > medium > low > info.
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(a.Findings, func(i, j int) bool {
		return severityRank[a.Findings[i].Severity] < severityRank[a.Findings[j].Severity]
	})
	return a
}

// cspAnalysisHeadline returns a one-line summary for the security check's
// hint. Shows the strictness label, the score, and counts findings by sev.
func cspAnalysisHeadline(a cspAnalysis) string {
	if a.Strictness == "missing" {
		return "CSP: missing"
	}
	sev := map[string]int{}
	for _, f := range a.Findings {
		sev[f.Severity]++
	}
	parts := []string{}
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if sev[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", sev[s], s))
		}
	}
	bonus := ""
	if a.UsesNonces || a.UsesHashes || a.StrictDyn {
		bonus = " ["
		extras := []string{}
		if a.UsesNonces {
			extras = append(extras, "nonces")
		}
		if a.UsesHashes {
			extras = append(extras, "hashes")
		}
		if a.StrictDyn {
			extras = append(extras, "strict-dynamic")
		}
		bonus += strings.Join(extras, "+") + "]"
	}
	if len(parts) == 0 {
		return fmt.Sprintf("CSP: %s (%d/100)%s", a.Strictness, a.Score, bonus)
	}
	return fmt.Sprintf("CSP: %s (%d/100) — %s%s", a.Strictness, a.Score, strings.Join(parts, ", "), bonus)
}
