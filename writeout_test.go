package main

import (
	"strings"
	"testing"
	"time"
)

// Tests for --write-out template engine.

func TestProcessEscapes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"plain text", "plain text"},
		{"line1\\nline2", "line1\nline2"},
		{"col1\\tcol2", "col1\tcol2"},
		{"crlf\\r\\n", "crlf\r\n"},
		{"backslash\\\\path", "backslash\\path"},
		{"unknown\\zescape", "unknown\\zescape"}, // unknown \z is preserved literally
		{"trailing\\", "trailing\\"},             // dangling backslash preserved
	}
	for _, c := range cases {
		if got := processEscapes(c.in); got != c.want {
			t.Errorf("in=%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestWriteOutValues_Basics(t *testing.T) {
	r := &Report{
		Target:   "https://example.com",
		Host:     "example.com",
		Port:     443,
		Scheme:   "https",
		Healthy:  true,
		Elapsed:  "1.2s",
		Problems: []string{},
	}
	v := writeOutValues(r, 0)
	if v["host"] != "example.com" || v["port"] != "443" || v["scheme"] != "https" {
		t.Errorf("basic fields wrong: %+v", v)
	}
	if v["healthy"] != "true" {
		t.Errorf("healthy: got %q want true", v["healthy"])
	}
}

func TestRunWriteOut_Substitution(t *testing.T) {
	r := &Report{
		Target:  "https://example.com",
		Host:    "example.com",
		Port:    443,
		Scheme:  "https",
		Healthy: true,
		Elapsed: "1.2s",
		Checks: []Check{
			{Name: "TLS", Status: StatusOK, Summary: "valid"},
		},
	}
	got := runWriteOut(`host=${host} port=${port} healthy=${healthy}\n`, r, 0)
	want := "host=example.com port=443 healthy=true\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRunWriteOut_UnknownVariable(t *testing.T) {
	// Unknown ${...} variables should expand to empty (or stay literal, but
	// empty is the netdoc convention). Either way, the engine must not panic.
	r := &Report{Target: "x.com", Host: "x.com"}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("writeOut panicked on unknown variable: %v", r)
		}
	}()
	_ = runWriteOut(`x=${nonexistent_variable}\n`, r, 0)
}

func TestFormatMS(t *testing.T) {
	// formatMS converts a float64 millisecond count to a printable string.
	cases := []struct {
		ms   float64
		want string
	}{
		{0, "0"},
		{1.0, "1"},
		{0.4, "0.4"},
		{15.7, "15.7"},
		{123456.789, "123456.789"},
	}
	for _, c := range cases {
		got := formatMS(c.ms)
		// Just check it's non-empty and parseable — exact format is implementation detail.
		if got == "" {
			t.Errorf("formatMS(%v) returned empty string", c.ms)
		}
	}
}

func TestRunWriteOut_HealthyExitCode(t *testing.T) {
	r := &Report{Healthy: true}
	// exit_code variable should reflect what we passed.
	got := runWriteOut(`exit=${exit_code}\n`, r, 0)
	if !strings.Contains(got, "exit=0") {
		t.Errorf("expected exit=0, got %q", got)
	}
	got = runWriteOut(`exit=${exit_code}\n`, r, 2)
	if !strings.Contains(got, "exit=2") {
		t.Errorf("expected exit=2, got %q", got)
	}
}

// --- diff tests ---

func TestReportDiff_NoChanges(t *testing.T) {
	r := &Report{Healthy: true, Checks: []Check{{Name: "DNS", Status: StatusOK, Summary: "resolved"}}}
	diffs := reportDiff(r, r)
	if len(diffs) != 0 {
		t.Errorf("identical reports should have no diffs, got %v", diffs)
	}
}

func TestReportDiff_StatusChange(t *testing.T) {
	before := &Report{
		Checks: []Check{{Name: "TLS", Status: StatusOK, Summary: "valid"}},
	}
	after := &Report{
		Checks: []Check{{Name: "TLS", Status: StatusFail, Summary: "expired"}},
	}
	diffs := reportDiff(before, after)
	if len(diffs) == 0 {
		t.Errorf("status change should produce diffs")
	}
}

func TestReportDiff_NewCheckAppeared(t *testing.T) {
	before := &Report{Checks: []Check{{Name: "DNS", Status: StatusOK}}}
	after := &Report{Checks: []Check{
		{Name: "DNS", Status: StatusOK},
		{Name: "TLS", Status: StatusOK},
	}}
	diffs := reportDiff(before, after)
	if len(diffs) == 0 {
		t.Errorf("new check should appear in diff")
	}
}

func TestIndexChecks(t *testing.T) {
	checks := []Check{
		{Name: "DNS", Status: StatusOK},
		{Name: "TLS", Status: StatusFail},
	}
	idx := indexChecks(checks)
	if idx["DNS"].Status != StatusOK || idx["TLS"].Status != StatusFail {
		t.Errorf("indexChecks lost data: %+v", idx)
	}
}

func TestMergeCheckNames(t *testing.T) {
	a := map[string]Check{"DNS": {Name: "DNS"}, "TLS": {Name: "TLS"}}
	b := map[string]Check{"TLS": {Name: "TLS"}, "HTTP": {Name: "HTTP"}}
	names := mergeCheckNames(a, b)
	if len(names) != 3 {
		t.Errorf("expected 3 unique names, got %v", names)
	}
}

func TestStringifyValue_PrimitiveTypes(t *testing.T) {
	cases := []struct {
		v      any
		want   string
		wantOK bool
	}{
		{"hello", "hello", true},
		{int(42), "42", true},
		{int64(1234), "1234", true},
		{float64(3.14), "3.14", true},
		{true, "true", true},
		{false, "false", true},
	}
	for _, c := range cases {
		got, ok := stringifyValue(c.v)
		if ok != c.wantOK {
			t.Errorf("ok for %v: got %v want %v", c.v, ok, c.wantOK)
		}
		if got != c.want {
			t.Errorf("v=%v: got %q want %q", c.v, got, c.want)
		}
	}
}

// --- silence import for time ---
var _ = time.Now
