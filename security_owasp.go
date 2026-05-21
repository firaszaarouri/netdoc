package main

import (
	"net/http"
	"strings"
)

// OWASP Secure Headers Project compliance profile. The project publishes
// a concrete recommended set of HTTP security headers with specific values;
// we evaluate the observed headers against that profile and report per-rule
// pass/fail. Complements netdoc's existing 9-header grader (which assigns
// a 0-100 score); this adds a binary pass/fail against an authoritative
// industry baseline.
//
// Reference: https://owasp.org/www-project-secure-headers/ (current 2026
// recommendation; ruleset embedded as of 2026-05-20).

// owaspRule defines one header check.
type owaspRule struct {
	Header       string                       // canonical header name
	Required     bool                         // OWASP says MUST have this
	ValueCheck   func(string) (bool, string)  // returns (passes, why if not)
	WhyRequired  string
}

// owaspRules is the rule set per OWASP Secure Headers Project's recommendations.
var owaspRules = []owaspRule{
	{
		Header:      "Strict-Transport-Security",
		Required:    true,
		WhyRequired: "Forces HTTPS-only access",
		ValueCheck: func(v string) (bool, string) {
			if v == "" {
				return false, "header not present"
			}
			lv := strings.ToLower(v)
			if !strings.Contains(lv, "max-age=") {
				return false, "missing max-age"
			}
			if !strings.Contains(lv, "includesubdomains") {
				return false, "missing includeSubDomains (OWASP-recommended)"
			}
			return true, ""
		},
	},
	{
		Header:      "Content-Security-Policy",
		Required:    true,
		WhyRequired: "Mitigates XSS / clickjacking",
		ValueCheck: func(v string) (bool, string) {
			if v == "" {
				return false, "header not present"
			}
			lv := strings.ToLower(v)
			if strings.Contains(lv, "unsafe-inline") {
				return false, "contains 'unsafe-inline'"
			}
			if strings.Contains(lv, "unsafe-eval") {
				return false, "contains 'unsafe-eval'"
			}
			if !strings.Contains(lv, "default-src") && !strings.Contains(lv, "script-src") {
				return false, "no default-src or script-src directive"
			}
			return true, ""
		},
	},
	{
		Header:      "X-Frame-Options",
		Required:    false, // either XFO or CSP frame-ancestors satisfies
		WhyRequired: "Prevents clickjacking via iframe embedding",
		ValueCheck: func(v string) (bool, string) {
			if v == "" {
				return false, "header not present (CSP frame-ancestors also acceptable)"
			}
			lv := strings.ToUpper(strings.TrimSpace(v))
			if lv != "DENY" && lv != "SAMEORIGIN" {
				return false, "value should be DENY or SAMEORIGIN"
			}
			return true, ""
		},
	},
	{
		Header:      "X-Content-Type-Options",
		Required:    true,
		WhyRequired: "Prevents MIME-type sniffing",
		ValueCheck: func(v string) (bool, string) {
			if strings.ToLower(strings.TrimSpace(v)) != "nosniff" {
				return false, "must be 'nosniff'"
			}
			return true, ""
		},
	},
	{
		Header:      "Referrer-Policy",
		Required:    true,
		WhyRequired: "Controls referrer leakage to other origins",
		ValueCheck: func(v string) (bool, string) {
			if v == "" {
				return false, "header not present"
			}
			lv := strings.ToLower(v)
			weak := []string{"unsafe-url", "origin-when-cross-origin"}
			for _, w := range weak {
				if strings.Contains(lv, w) {
					return false, "policy '" + w + "' is weak"
				}
			}
			return true, ""
		},
	},
	{
		Header:      "Permissions-Policy",
		Required:    true,
		WhyRequired: "Restricts powerful browser APIs (camera, mic, geolocation)",
		ValueCheck: func(v string) (bool, string) {
			if v == "" {
				return false, "header not present (limits powerful API isolation)"
			}
			return true, ""
		},
	},
	{
		Header:      "Cross-Origin-Opener-Policy",
		Required:    true,
		WhyRequired: "Isolates browsing-context group from cross-origin",
		ValueCheck: func(v string) (bool, string) {
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv != "same-origin" && lv != "same-origin-allow-popups" {
				return false, "value should be 'same-origin' or 'same-origin-allow-popups'"
			}
			return true, ""
		},
	},
	{
		Header:      "Cross-Origin-Embedder-Policy",
		Required:    false, // recommended, paired with COOP for cross-origin isolation
		WhyRequired: "Enables cross-origin isolation when paired with COOP",
		ValueCheck: func(v string) (bool, string) {
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv == "require-corp" || lv == "credentialless" {
				return true, ""
			}
			return false, "missing or weak (set 'require-corp' or 'credentialless')"
		},
	},
	{
		Header:      "Cross-Origin-Resource-Policy",
		Required:    true,
		WhyRequired: "Prevents speculative side-channel attacks (Spectre)",
		ValueCheck: func(v string) (bool, string) {
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv != "same-origin" && lv != "same-site" && lv != "cross-origin" {
				return false, "value should be same-origin / same-site / cross-origin"
			}
			return true, ""
		},
	},
}

// owaspComplianceResult records per-rule pass/fail + overall summary.
type owaspComplianceResult struct {
	Passes  bool                    `json:"passes"`
	Score   int                     `json:"score"`  // 0-100
	Rules   []owaspRuleResult       `json:"rules"`
}

// owaspRuleResult is one rule's outcome.
type owaspRuleResult struct {
	Header   string `json:"header"`
	Required bool   `json:"required"`
	Passes   bool   `json:"passes"`
	Reason   string `json:"reason,omitempty"`
}

// evaluateOWASPHeaders checks observed headers against the OWASP profile.
func evaluateOWASPHeaders(h http.Header) owaspComplianceResult {
	res := owaspComplianceResult{}
	requiredPass, requiredTotal := 0, 0
	optionalPass, optionalTotal := 0, 0
	for _, rule := range owaspRules {
		v := h.Get(rule.Header)
		passes, reason := rule.ValueCheck(v)
		res.Rules = append(res.Rules, owaspRuleResult{
			Header:   rule.Header,
			Required: rule.Required,
			Passes:   passes,
			Reason:   reason,
		})
		if rule.Required {
			requiredTotal++
			if passes {
				requiredPass++
			}
		} else {
			optionalTotal++
			if passes {
				optionalPass++
			}
		}
	}
	// Pass overall iff every REQUIRED rule passes.
	res.Passes = requiredPass == requiredTotal
	// Score: required rules carry 80%, optional 20%.
	if requiredTotal > 0 {
		res.Score = (requiredPass * 80 / requiredTotal)
	}
	if optionalTotal > 0 {
		res.Score += (optionalPass * 20 / optionalTotal)
	}
	return res
}

// owaspHeadline returns "OWASP: 8/9 pass" for the hint line.
func owaspHeadline(r owaspComplianceResult) string {
	if len(r.Rules) == 0 {
		return ""
	}
	pass := 0
	for _, rule := range r.Rules {
		if rule.Passes {
			pass++
		}
	}
	verdict := "✓"
	if !r.Passes {
		verdict = "✗"
	}
	return "OWASP " + verdict + " " + itoa(pass) + "/" + itoa(len(r.Rules))
}
