package main

import (
	"net/http"
	"strings"
	"testing"
)

// Tests for the 9-header security grader. The grader is the netdoc
// differentiator — securityheaders.com and Mozilla Observatory grade
// similarly but no other CLI does this with this depth. Pin its math.

func mkHeader(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestGradeSecurityHeaders_AllAbsent(t *testing.T) {
	results, score := gradeSecurityHeaders(mkHeader())
	if score != 0 {
		t.Errorf("all-absent score: got %d want 0", score)
	}
	for _, r := range results {
		if r.Present {
			t.Errorf("%s: Present=true on empty header set", r.Short)
		}
		if r.Pass {
			t.Errorf("%s: Pass=true on absent header", r.Short)
		}
	}
}

func TestGradeSecurityHeaders_PreloadEligible(t *testing.T) {
	// Strict-Transport-Security with max-age >= 1yr + includeSubDomains + preload.
	results, score := gradeSecurityHeaders(mkHeader(
		"Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload",
	))
	var hsts *secHeaderResult
	for i := range results {
		if results[i].Short == "HSTS" {
			hsts = &results[i]
			break
		}
	}
	if hsts == nil || !hsts.Pass {
		t.Fatalf("HSTS should pass with full preload directives")
	}
	if hsts.Reason != "preload-eligible" {
		t.Errorf("HSTS reason: got %q want preload-eligible", hsts.Reason)
	}
	if score != 20 {
		t.Errorf("HSTS-only score: got %d want 20", score)
	}
}

func TestGradeSecurityHeaders_HSTS_ShortMaxAge(t *testing.T) {
	// max-age too short for preload — should fail.
	results, _ := gradeSecurityHeaders(mkHeader(
		"Strict-Transport-Security", "max-age=3600", // 1 hour
	))
	for _, r := range results {
		if r.Short == "HSTS" {
			if r.Pass {
				t.Errorf("HSTS with 1-hour max-age should NOT pass (need ≥6mo soft, ≥1yr hard)")
			}
			if !strings.Contains(r.Reason, "max-age") {
				t.Errorf("HSTS reason should mention max-age, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeSecurityHeaders_HSTS_SoftPass(t *testing.T) {
	// max-age >= 6 months but missing preload — should soft-pass.
	results, _ := gradeSecurityHeaders(mkHeader(
		"Strict-Transport-Security", "max-age=15768000", // 6 months
	))
	for _, r := range results {
		if r.Short == "HSTS" {
			if !r.Pass {
				t.Errorf("HSTS with 6mo max-age should soft-pass")
			}
			if r.Reason == "" || !strings.Contains(r.Reason, "missing") {
				t.Errorf("soft-pass should explain what's missing in reason, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeCSP_StrictPolicy(t *testing.T) {
	// CSP Level 3 strict baseline: object-src 'none', base-uri set,
	// form-action set, frame-ancestors set, reporting endpoint. The
	// minimal "default-src 'self'; script-src 'self'" is a 2019 baseline
	// and doesn't score strict in 2026.
	results, _ := gradeSecurityHeaders(mkHeader(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self' cdn.example.com; style-src 'self'; "+
			"object-src 'none'; base-uri 'self'; form-action 'self'; "+
			"frame-ancestors 'self'; report-to default; upgrade-insecure-requests",
	))
	for _, r := range results {
		if r.Short == "CSP" {
			if !r.Pass {
				t.Errorf("strict CSP should pass, reason: %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeCSP_UnsafeInline(t *testing.T) {
	results, _ := gradeSecurityHeaders(mkHeader(
		"Content-Security-Policy", "default-src 'self' 'unsafe-inline'",
	))
	for _, r := range results {
		if r.Short == "CSP" {
			if r.Pass {
				t.Errorf("CSP with unsafe-inline should NOT pass")
			}
			if !strings.Contains(r.Reason, "unsafe-inline") {
				t.Errorf("reason should call out unsafe-inline, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeCSP_NoDefaultSrc(t *testing.T) {
	results, _ := gradeSecurityHeaders(mkHeader(
		"Content-Security-Policy", "script-src 'self'",
	))
	for _, r := range results {
		if r.Short == "CSP" {
			if r.Pass {
				t.Errorf("CSP without default-src should NOT pass")
			}
			if !strings.Contains(r.Reason, "default-src") {
				t.Errorf("reason should mention default-src, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeCSP_WildcardScriptSrc(t *testing.T) {
	results, _ := gradeSecurityHeaders(mkHeader(
		"Content-Security-Policy", "default-src 'self'; script-src 'self' *",
	))
	for _, r := range results {
		if r.Short == "CSP" {
			if r.Pass {
				t.Errorf("CSP with wildcard in script-src should NOT pass")
			}
			if !strings.Contains(r.Reason, "wildcard") {
				t.Errorf("reason should mention wildcard, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeXFO_DENY(t *testing.T) {
	results, _ := gradeSecurityHeaders(mkHeader("X-Frame-Options", "DENY"))
	for _, r := range results {
		if r.Short == "XFO" {
			if !r.Pass {
				t.Errorf("XFO=DENY should pass")
			}
			return
		}
	}
}

func TestGradeXFO_SAMEORIGIN(t *testing.T) {
	results, _ := gradeSecurityHeaders(mkHeader("X-Frame-Options", "SAMEORIGIN"))
	for _, r := range results {
		if r.Short == "XFO" {
			if !r.Pass {
				t.Errorf("XFO=SAMEORIGIN should pass")
			}
			return
		}
	}
}

func TestGradeXFO_AcceptsCSPFrameAncestors(t *testing.T) {
	// Modern replacement — CSP frame-ancestors covers the same threat.
	results, _ := gradeSecurityHeaders(mkHeader(
		"X-Frame-Options", "ALLOWALL", // would normally fail
		"Content-Security-Policy", "frame-ancestors 'self'",
	))
	for _, r := range results {
		if r.Short == "XFO" {
			if !r.Pass {
				t.Errorf("XFO with CSP frame-ancestors should pass (modern replacement)")
			}
			if !strings.Contains(r.Reason, "frame-ancestors") {
				t.Errorf("should acknowledge frame-ancestors in reason, got %q", r.Reason)
			}
			return
		}
	}
}

func TestGradeFullPosture_PerfectScore(t *testing.T) {
	// A fully-deployed posture — every header present with passing values.
	// Weights: HSTS(20) + CSP(20) + XFO(12) + XCTO(10) + Ref(8) +
	//          COOP(8) + Perm(5) + COEP(4) + CORP(4) + OAC(3) +
	//          DocPolicy(3) + Reporting(3) = 100.
	h := mkHeader(
		"Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload",
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "+
			"form-action 'self'; frame-ancestors 'self'; report-to default; upgrade-insecure-requests",
		"X-Frame-Options", "DENY",
		"X-Content-Type-Options", "nosniff",
		"Referrer-Policy", "no-referrer",
		"Cross-Origin-Opener-Policy", "same-origin",
		"Permissions-Policy", "geolocation=()",
		"Cross-Origin-Embedder-Policy", "require-corp",
		"Cross-Origin-Resource-Policy", "same-origin",
		"Origin-Agent-Cluster", "?1",
		"Document-Policy", "document-write=?0",
		"Reporting-Endpoints", `default="/reports"`,
	)
	_, score := gradeSecurityHeaders(h)
	if score != 100 {
		t.Errorf("perfect posture score: got %d want 100", score)
	}
}

func TestGradeSecurityHeaders_WeightsSumTo100(t *testing.T) {
	// Defensive: total weight across all 9 headers must be exactly 100
	// so a perfect posture maps to 100% / A grade. This guards future
	// edits from accidentally drifting the total.
	results, _ := gradeSecurityHeaders(mkHeader())
	total := 0
	for _, r := range results {
		total += r.Weight
	}
	if total != 100 {
		t.Errorf("header weights sum to %d, want 100 (drift in security_headers.go grading config)", total)
	}
}

func TestWildcardInScriptSrc(t *testing.T) {
	cases := []struct {
		csp  string
		want bool
	}{
		{"default-src 'self'; script-src 'self'", false},
		{"script-src 'self' *", true},
		{"script-src 'self' *.example.com", false}, // schema-qualified wildcard is NOT bare *
		{"script-src data:", true},
		{"script-src blob:", true},
		{"script-src 'self' https://cdn.example.com", false},
	}
	for _, c := range cases {
		got := wildcardInScriptSrc(c.csp)
		if got != c.want {
			t.Errorf("csp %q: got %v want %v", c.csp, got, c.want)
		}
	}
}
