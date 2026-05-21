package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Security-header grading. Inspired by Mozilla Observatory / securityheaders.com
// but scoped to what's actually useful as a one-command diagnostic: presence +
// best-practice value check per header, then a 0-100 score and letter grade.
//
// No competitor CLI does this well (per 2026 audit) — testssl.sh covers TLS,
// curl/httpie just dump headers, ProjectDiscovery's httpx surfaces CSP without
// grading. This check is the netdoc differentiator.

// secHeaderResult records one graded header.
type secHeaderResult struct {
	Name    string `json:"name"`
	Short   string `json:"short"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Pass    bool   `json:"pass"`
	Reason  string `json:"reason,omitempty"`
	Weight  int    `json:"weight"`
}

// gradeSecurityHeaders inspects an http.Header set and returns the per-header
// findings plus an overall 0-100 score. The scoring weights are opinionated
// but transparent — every header carries its weight in the JSON detail so a
// consumer can disagree with the totals and recompute.
func gradeSecurityHeaders(h http.Header) (results []secHeaderResult, score int) {
	defs := []struct {
		name   string
		short  string
		weight int
		grade  func(values []string, all http.Header) (bool, string, string) // returns pass, value-summary, reason
	}{
		// Weights sum to 100. HSTS + CSP carry the dominant 20 each.
		{"Strict-Transport-Security", "HSTS", 20, gradeHSTS},
		{"Content-Security-Policy", "CSP", 20, gradeCSP},
		{"X-Frame-Options", "XFO", 12, gradeXFO},
		{"X-Content-Type-Options", "XCTO", 10, gradeXCTO},
		{"Referrer-Policy", "Ref-Policy", 8, gradeReferrer},
		{"Cross-Origin-Opener-Policy", "COOP", 8, gradePresenceOnly},
		{"Permissions-Policy", "Permissions", 5, gradePresenceOnly},
		{"Cross-Origin-Embedder-Policy", "COEP", 4, gradePresenceOnly},
		{"Cross-Origin-Resource-Policy", "CORP", 4, gradePresenceOnly},
		// CSP Level 3 / modern hardening headers.
		{"Origin-Agent-Cluster", "OAC", 3, gradeOriginAgentCluster},
		{"Document-Policy", "Doc-Policy", 3, gradePresenceOnly},
		{"Reporting-Endpoints", "Reporting", 3, gradePresenceOnly},
	}
	for _, def := range defs {
		values := h.Values(def.name)
		r := secHeaderResult{Name: def.name, Short: def.short, Weight: def.weight}
		if len(values) > 0 {
			r.Present = true
			pass, vsum, reason := def.grade(values, h)
			r.Value = vsum
			r.Pass = pass
			r.Reason = reason
			if pass {
				score += def.weight
			}
		} else {
			r.Reason = "header absent"
		}
		results = append(results, r)
	}
	return results, score
}

// gradeHSTS audits Strict-Transport-Security against Chromium HSTS preload
// list eligibility criteria (https://hstspreload.org/#submission-requirements):
//   - max-age >= 31536000 (1 year)
//   - includeSubDomains directive present
//   - preload directive present
//
// All three present → "preload-eligible"; missing any → fail with the
// specific directive named so the user can fix it. We don't query the
// actual Chromium static list (that data is 6 MB and rotates weekly);
// our pass means "you've done your part to be eligible".
func gradeHSTS(values []string, _ http.Header) (bool, string, string) {
	val := strings.Join(values, ", ")
	directives := parseDirectives(val)
	maxAgeStr := directives["max-age"]
	maxAge, _ := strconv.ParseInt(maxAgeStr, 10, 64)
	_, hasInclude := directives["includesubdomains"]
	_, hasPreload := directives["preload"]

	var issues []string
	if maxAge < 31536000 {
		issues = append(issues, fmt.Sprintf("max-age=%d (<1yr — preload requires ≥31536000)", maxAge))
	}
	if !hasInclude {
		issues = append(issues, "missing includeSubDomains")
	}
	if !hasPreload {
		issues = append(issues, "missing preload directive")
	}
	if len(issues) == 0 {
		return true, val, "preload-eligible"
	}
	// Soft pass — still credit if max-age >= 6 months even when preload
	// criteria aren't all met. Preserves the v1.x pass threshold and lets
	// the issues field carry the upgrade-path information.
	if maxAge >= 15768000 {
		return true, val, strings.Join(issues, ", ")
	}
	return false, val, strings.Join(issues, ", ")
}

// gradeCSP — delegates to the full CSP Level 3 parser + strictness scorer
// in csp_parser.go. Passes when the policy reaches at least "moderate"
// strictness (score ≥ 60). The hint surfaces the strictness label, score,
// and a sorted finding count by severity so users can see exactly what
// makes the policy strict / moderate / loose.
func gradeCSP(values []string, _ http.Header) (bool, string, string) {
	val := strings.Join(values, ", ")
	policy := parseCSP(val)
	analysis := evaluateCSP(policy)
	headline := cspAnalysisHeadline(analysis)
	switch analysis.Strictness {
	case "strict", "moderate":
		return true, truncate(val, 56), headline
	}
	// loose / missing — gather the top critical/high findings into the
	// reason so the CLI hint names what's wrong instead of just "fail".
	var parts []string
	for _, f := range analysis.Findings {
		if f.Severity == "critical" || f.Severity == "high" {
			parts = append(parts, f.Issue)
		}
		if len(parts) >= 3 {
			break
		}
	}
	if len(parts) == 0 {
		return false, truncate(val, 56), headline
	}
	return false, truncate(val, 56), headline + " · " + strings.Join(parts, "; ")
}

// wildcardInScriptSrc returns true when script-src list contains "*" (alone,
// not "*.example.com") or a schema source like "data:" or "blob:".
func wildcardInScriptSrc(csp string) bool {
	i := strings.Index(csp, "script-src")
	if i < 0 {
		return false
	}
	end := strings.IndexAny(csp[i:], ";")
	region := csp
	if end >= 0 {
		region = csp[i : i+end]
	} else {
		region = csp[i:]
	}
	for _, tok := range strings.Fields(region) {
		if tok == "*" || tok == "data:" || tok == "blob:" {
			return true
		}
	}
	return false
}

// gradeXFO — passes if value is DENY or SAMEORIGIN. Also passes if CSP's
// frame-ancestors directive is set (the modern replacement; XFO is legacy).
func gradeXFO(values []string, all http.Header) (bool, string, string) {
	val := strings.ToUpper(strings.TrimSpace(values[0]))
	if val == "DENY" || val == "SAMEORIGIN" {
		return true, values[0], ""
	}
	// CSP frame-ancestors covers the same threat surface; accept either.
	if csp := all.Get("Content-Security-Policy"); csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		return true, values[0], "CSP frame-ancestors also set"
	}
	return false, values[0], "neither DENY nor SAMEORIGIN"
}

// gradeXCTO — must be exactly "nosniff" (case-insensitive).
func gradeXCTO(values []string, _ http.Header) (bool, string, string) {
	val := strings.ToLower(strings.TrimSpace(values[0]))
	if val == "nosniff" {
		return true, values[0], ""
	}
	return false, values[0], "expected nosniff"
}

// gradeReferrer — passes for any value (we don't enforce a specific policy
// since the right choice is application-dependent; merely setting one signals
// the author thought about it).
func gradeReferrer(values []string, _ http.Header) (bool, string, string) {
	return true, values[0], ""
}

// gradeOriginAgentCluster — Origin-Agent-Cluster requires "?1" to opt the
// origin into its own agent cluster (process isolation against side-channel
// attacks like Spectre). Other values are no-ops per WHATWG HTML Living
// Standard §4.10.2.
func gradeOriginAgentCluster(values []string, _ http.Header) (bool, string, string) {
	val := strings.TrimSpace(values[0])
	if val == "?1" {
		return true, val, ""
	}
	return false, val, "expected ?1 to enable origin-agent-cluster"
}

// gradePresenceOnly — passes on presence (COOP, COEP, CORP, Permissions-Policy
// all have meaningful default values, so the act of setting them is itself the
// signal).
func gradePresenceOnly(values []string, _ http.Header) (bool, string, string) {
	return true, truncate(values[0], 48), ""
}

// detectDeprecatedHeaders flags response headers that were security controls
// historically but are now deprecated / counter-productive:
//   - Public-Key-Pins / Public-Key-Pins-Report-Only — HPKP, retired by browsers
//   - Expect-CT — retired now that CT is mandatory in cert chains
//   - X-XSS-Protection — Chrome/Edge dropped support; can enable XSS-rich bugs
//   - Pragma — HTTP/1.0 cache directive superseded by Cache-Control
func detectDeprecatedHeaders(h http.Header) []string {
	candidates := []string{
		"Public-Key-Pins",
		"Public-Key-Pins-Report-Only",
		"Expect-CT",
		"X-XSS-Protection",
		"Pragma",
	}
	var out []string
	for _, name := range candidates {
		if h.Get(name) != "" {
			out = append(out, name)
		}
	}
	return out
}

// detectInfoLeakHeaders flags headers that leak software-version info to
// attackers. The names + versions help attackers match known CVEs against
// the deployment. Modern hardening guides (OWASP Secure Headers, Hardenize)
// recommend stripping these at the front-door proxy.
func detectInfoLeakHeaders(h http.Header) []string {
	candidates := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Generator",
		"X-Drupal-Cache",
		"X-Drupal-Dynamic-Cache",
	}
	var out []string
	for _, name := range candidates {
		if v := h.Get(name); v != "" {
			out = append(out, name+": "+truncate(v, 30))
		}
	}
	return out
}

// parseDirectives splits a "name=value; flag; name=value" header value into a
// map. Standalone tokens map to themselves (so callers can check "preload" via
// `directives["preload"] == "preload"` or just `_, ok := directives["preload"]`).
func parseDirectives(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '='); i >= 0 {
			out[strings.ToLower(strings.TrimSpace(part[:i]))] = strings.TrimSpace(part[i+1:])
		} else {
			out[strings.ToLower(part)] = part
		}
	}
	return out
}

// scoreToGrade converts a 0-100 score to a letter grade.
func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// checkSecurityHeaders grades the response headers from the trace. Only
// meaningful for HTTPS targets and successful HTTP responses; otherwise skip.
func (d *diagnosis) checkSecurityHeaders() Check {
	c := Check{Name: "Security"}
	if d.trace == nil || d.trace.Headers == nil {
		c.Status = StatusSkip
		c.Summary = "skipped — no HTTP response to grade"
		return c
	}
	if d.scheme != "https" {
		c.Status = StatusSkip
		c.Summary = "skipped — plain HTTP target (security headers are HTTPS-relevant)"
		return c
	}

	results, score := gradeSecurityHeaders(d.trace.Headers)
	grade := scoreToGrade(score)
	cookies := auditCookies(d.trace.Headers.Values("Set-Cookie"))
	deprecated := detectDeprecatedHeaders(d.trace.Headers)
	infoLeak := detectInfoLeakHeaders(d.trace.Headers)

	var present, missing []string
	for _, r := range results {
		if r.Pass {
			present = append(present, r.Short)
		} else {
			missing = append(missing, r.Short)
		}
	}

	c.Detail = map[string]any{
		"score":   score,
		"grade":   grade,
		"headers": results,
	}
	if len(cookies) > 0 {
		c.Detail["cookies"] = cookies
	}
	if len(deprecated) > 0 {
		c.Detail["deprecated_headers"] = deprecated
	}
	if len(infoLeak) > 0 {
		c.Detail["info_leak_headers"] = infoLeak
	}

	// OWASP Secure Headers Project compliance — binary pass/fail per rule
	// against the authoritative industry baseline.
	owasp := evaluateOWASPHeaders(d.trace.Headers)
	c.Detail["owasp"] = owasp

	// Deep CSP Level 3 strictness analysis — surfaces nonce/hash/
	// strict-dynamic usage plus a sorted finding list with severity.
	var cspHeadline string
	if cspVal := strings.Join(d.trace.Headers.Values("Content-Security-Policy"), ", "); cspVal != "" {
		cspAnalysisResult := evaluateCSP(parseCSP(cspVal))
		c.Detail["csp_analysis"] = cspAnalysisResult
		cspHeadline = cspAnalysisHeadline(cspAnalysisResult)
	}

	c.Summary = fmt.Sprintf("%d/100 (%s) — %d of %d headers pass",
		score, grade, len(present), len(results))

	var hintLines []string
	if len(present) > 0 {
		hintLines = append(hintLines, "present: "+strings.Join(present, " · "))
	}
	if len(missing) > 0 {
		hintLines = append(hintLines, "missing: "+strings.Join(missing, " · "))
	}
	if summary := cookieSummary(cookies); summary != "" {
		hintLines = append(hintLines, summary)
	}
	if len(deprecated) > 0 {
		hintLines = append(hintLines, "deprecated: "+strings.Join(deprecated, ", "))
	}
	if len(infoLeak) > 0 {
		hintLines = append(hintLines, "info-leak: "+strings.Join(infoLeak, ", "))
	}
	if v := owaspHeadline(owasp); v != "" {
		hintLines = append(hintLines, v)
	}
	if cspHeadline != "" {
		hintLines = append(hintLines, cspHeadline)
	}
	c.Hint = strings.Join(hintLines, "\n")

	switch {
	case score >= 80:
		c.Status = StatusOK
	case score >= 60:
		c.Status = StatusWarn
	default:
		c.Status = StatusWarn
	}
	return c
}
