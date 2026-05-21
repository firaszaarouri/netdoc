package main

import (
	"strings"
	"testing"
)

// Tests for HTML / Markdown report formatters.

func sampleReport() Report {
	return Report{
		Target:  "https://example.com",
		Host:    "example.com",
		Port:    443,
		Scheme:  "https",
		Healthy: false,
		Elapsed: "1.2s",
		Checks: []Check{
			{Name: "DNS", Status: StatusOK, Summary: "resolved in 20ms"},
			{Name: "TLS", Status: StatusFail, Summary: "certificate expired", Hint: "  not before: 2024-01-01\n  not after:  2025-01-01"},
		},
		Problems: []string{"TLS — certificate expired"},
		FixFirst: "TLS — certificate expired",
	}
}

func TestRenderHTML_Contains(t *testing.T) {
	html := renderHTML(sampleReport())

	for _, want := range []string{
		"<!doctype html>",
		"netdoc report",
		"example.com",
		"✗ fail",
		"Fix first",
		"certificate expired",
		"not before",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestRenderHTML_HealthyOmitsFixFirst(t *testing.T) {
	r := sampleReport()
	r.Healthy = true
	r.FixFirst = ""
	r.Problems = nil
	html := renderHTML(r)
	if strings.Contains(html, "Fix first") {
		t.Errorf("healthy report should not show Fix first block")
	}
}

func TestRenderHTML_EscapesUnsafe(t *testing.T) {
	r := sampleReport()
	r.Target = "<script>alert(1)</script>"
	r.FixFirst = "<img onerror=alert(1)>"
	html := renderHTML(r)
	// Raw <script> must not appear unescaped — that would be a stored-XSS
	// risk if the HTML is shared via email or wiki.
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img onerror") {
		t.Errorf("HTML report failed to escape unsafe HTML in user-controlled fields")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("HTML report should escape angle brackets")
	}
}

func TestRenderMarkdown_Contains(t *testing.T) {
	md := renderMarkdown(sampleReport())
	for _, want := range []string{
		"# netdoc report",
		"`https://example.com`",
		"❌ 1 problem",
		"🔧 **Fix first:**",
		"| **DNS** |",
		"| **TLS** |",
		"### TLS",
		"```",
		"not before",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown report missing %q", want)
		}
	}
}

func TestRenderMarkdown_HealthyVerdict(t *testing.T) {
	r := sampleReport()
	r.Healthy = true
	r.Problems = nil
	r.FixFirst = ""
	md := renderMarkdown(r)
	if !strings.Contains(md, "✅ Healthy") {
		t.Errorf("healthy markdown should show ✅ Healthy header")
	}
	if strings.Contains(md, "🔧 **Fix first:**") {
		t.Errorf("healthy markdown should not show Fix first")
	}
}

func TestRenderMarkdown_TableSeparator(t *testing.T) {
	md := renderMarkdown(sampleReport())
	if !strings.Contains(md, "|---|---|---|") {
		t.Errorf("markdown table separator row missing — table syntax broken")
	}
}

func TestRenderMarkdown_EscapesPipes(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Summary = "value | with | pipes"
	md := renderMarkdown(r)
	if strings.Contains(md, "| value | with | pipes |") {
		t.Errorf("markdown failed to escape pipes in cell content (would break the table)")
	}
	if !strings.Contains(md, `value \| with \| pipes`) {
		t.Errorf("markdown should escape pipes as \\|")
	}
}
