package main

import (
	"strings"
	"testing"
)

func TestParseCSP_BasicSplit(t *testing.T) {
	p := parseCSP("default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'")
	want := map[string][]string{
		"default-src": {"'self'"},
		"script-src":  {"'self'", "cdn.example.com"},
		"object-src":  {"'none'"},
	}
	for name, exp := range want {
		got, ok := p.Directives[name]
		if !ok {
			t.Fatalf("missing directive %q", name)
		}
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			t.Errorf("directive %q: got %v want %v", name, got, exp)
		}
	}
}

func TestParseCSP_DirectiveFallback(t *testing.T) {
	// CSP3 §6.6.4 — script-src inherits from default-src when not set.
	p := parseCSP("default-src 'self' https:")
	got, ok := p.directive("script-src")
	if !ok {
		t.Fatal("script-src should fall back to default-src")
	}
	if len(got) != 2 || got[0] != "'self'" {
		t.Errorf("script-src fallback wrong: %v", got)
	}
}

func TestHasNonceHasHash(t *testing.T) {
	if !hasNonce([]string{"'self'", "'nonce-abc123'"}) {
		t.Error("hasNonce should detect nonce")
	}
	if hasNonce([]string{"'self'", "https://cdn"}) {
		t.Error("hasNonce false positive")
	}
	if !hasHash([]string{"'sha256-AAAA'", "'self'"}) {
		t.Error("hasHash should detect sha256")
	}
	if !hasHash([]string{"'sha384-BBBB'"}) {
		t.Error("hasHash should detect sha384")
	}
	if !hasHash([]string{"'sha512-CCCC'"}) {
		t.Error("hasHash should detect sha512")
	}
	if hasHash([]string{"'unsafe-inline'"}) {
		t.Error("hasHash false positive")
	}
}

func TestHasWildcard(t *testing.T) {
	cases := []struct {
		s    []string
		want bool
	}{
		{[]string{"'self'", "*"}, true},
		{[]string{"'self'", "data:"}, true},
		{[]string{"'self'", "blob:"}, true},
		{[]string{"'self'", "http:"}, true},
		{[]string{"'self'", "https:"}, true},
		{[]string{"'self'", "filesystem:"}, true},
		{[]string{"'self'", "*.example.com"}, false},
		{[]string{"'self'", "https://cdn.example.com"}, false},
		{[]string{"'self'"}, false},
	}
	for _, c := range cases {
		if got := hasWildcard(c.s); got != c.want {
			t.Errorf("hasWildcard(%v) = %v want %v", c.s, got, c.want)
		}
	}
}

func TestEvaluateCSP_Missing(t *testing.T) {
	a := evaluateCSP(nil)
	if a.Strictness != "missing" || a.Score != 0 {
		t.Errorf("nil should be missing/0, got %+v", a)
	}
	a = evaluateCSP(parseCSP(""))
	if a.Strictness != "missing" {
		t.Errorf("empty should be missing, got %s", a.Strictness)
	}
}

func TestEvaluateCSP_Loose(t *testing.T) {
	// Minimal "default-src 'self'" — passes the 2019 baseline but
	// fails the 2026 strict criteria (no object-src 'none', no base-uri,
	// no form-action, no frame-ancestors, no reporting, no
	// upgrade-insecure-requests).
	a := evaluateCSP(parseCSP("default-src 'self'; script-src 'self'"))
	if a.Strictness == "strict" {
		t.Errorf("minimal CSP should not be strict: %+v", a)
	}
	// Should have multiple findings.
	if len(a.Findings) < 3 {
		t.Errorf("expected ≥3 findings, got %d", len(a.Findings))
	}
}

func TestEvaluateCSP_Strict(t *testing.T) {
	csp := "default-src 'self'; script-src 'self'; object-src 'none'; " +
		"base-uri 'self'; form-action 'self'; frame-ancestors 'self'; " +
		"report-to default; upgrade-insecure-requests"
	a := evaluateCSP(parseCSP(csp))
	if a.Strictness != "strict" {
		t.Errorf("modern strict CSP should be strict, got %s (score %d)", a.Strictness, a.Score)
	}
}

func TestEvaluateCSP_UnsafeInline(t *testing.T) {
	a := evaluateCSP(parseCSP("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"))
	foundCrit := false
	for _, f := range a.Findings {
		if f.Severity == "critical" && strings.Contains(f.Issue, "unsafe-inline") {
			foundCrit = true
		}
	}
	if !foundCrit {
		t.Errorf("expected critical finding for unsafe-inline")
	}
}

func TestEvaluateCSP_NonceEscape(t *testing.T) {
	// unsafe-inline + nonce — nonce is the escape hatch, so the
	// unsafe-inline penalty should be skipped.
	a := evaluateCSP(parseCSP("script-src 'self' 'unsafe-inline' 'nonce-abc'"))
	for _, f := range a.Findings {
		if strings.Contains(f.Issue, "without nonce/hash") {
			t.Errorf("unsafe-inline with nonce should not be flagged as no-escape: %+v", f)
		}
	}
	if !a.UsesNonces {
		t.Error("UsesNonces should be true")
	}
}

func TestEvaluateCSP_StrictDynamicBonus(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; " +
		"object-src 'none'; base-uri 'self'; form-action 'self'; " +
		"frame-ancestors 'self'; report-to default"
	a := evaluateCSP(parseCSP(csp))
	if !a.StrictDyn {
		t.Error("StrictDyn should be true")
	}
	if !a.UsesNonces {
		t.Error("UsesNonces should be true")
	}
	// Score should benefit from the +10 strict-dynamic + +5 nonces bonuses.
	if a.Strictness != "strict" {
		t.Errorf("strict-dynamic + nonces should yield strict, got %s (score %d)", a.Strictness, a.Score)
	}
}

func TestEvaluateCSP_FindingsSorted(t *testing.T) {
	// Multiple severities; check they're sorted critical → high → medium → low.
	a := evaluateCSP(parseCSP("script-src 'self' *; default-src 'self'; upgrade-insecure-requests"))
	if len(a.Findings) < 2 {
		t.Fatalf("expected multiple findings, got %d", len(a.Findings))
	}
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for i := 1; i < len(a.Findings); i++ {
		if severityRank[a.Findings[i-1].Severity] > severityRank[a.Findings[i].Severity] {
			t.Errorf("findings unsorted at index %d: %s after %s",
				i, a.Findings[i].Severity, a.Findings[i-1].Severity)
		}
	}
}

func TestCSPAnalysisHeadline(t *testing.T) {
	// Missing policy.
	if got := cspAnalysisHeadline(cspAnalysis{Strictness: "missing"}); got != "CSP: missing" {
		t.Errorf("missing headline wrong: %q", got)
	}
	// Strict with no findings.
	got := cspAnalysisHeadline(cspAnalysis{Strictness: "strict", Score: 100})
	if !strings.Contains(got, "strict") || !strings.Contains(got, "100/100") {
		t.Errorf("strict headline missing strictness or score: %q", got)
	}
	// Loose with critical findings + bonus tag.
	got = cspAnalysisHeadline(cspAnalysis{
		Strictness: "loose",
		Score:      40,
		Findings:   []cspFinding{{Severity: "critical"}, {Severity: "high"}},
		UsesNonces: true,
		StrictDyn:  true,
	})
	if !strings.Contains(got, "1 critical") || !strings.Contains(got, "1 high") {
		t.Errorf("loose headline should count severity: %q", got)
	}
	if !strings.Contains(got, "nonces") || !strings.Contains(got, "strict-dynamic") {
		t.Errorf("bonus tag should mention nonces+strict-dynamic: %q", got)
	}
}
