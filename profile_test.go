package main

import (
	"testing"
)

// Tests for the --check / --profile filtering layer.

func TestParseCheckFilter_Empty(t *testing.T) {
	f, err := parseCheckFilter("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.allowsAll() {
		t.Errorf("empty filter should allow all checks")
	}
}

func TestParseCheckFilter_ValidNames(t *testing.T) {
	f, err := parseCheckFilter("tls,dns,mail")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.allowsAll() {
		t.Fatalf("non-empty filter should NOT allow all")
	}
	for _, name := range []string{"TLS", "tls", "Dns", "Mail"} {
		if !f.permits(name) {
			t.Errorf("filter should permit %q (case-insensitive)", name)
		}
	}
	for _, name := range []string{"HTTP", "Security", "Ports"} {
		if f.permits(name) {
			t.Errorf("filter should NOT permit %q", name)
		}
	}
}

func TestParseCheckFilter_Whitespace(t *testing.T) {
	// Whitespace tolerance — users often type "tls, dns" with a space.
	f, err := parseCheckFilter("tls,  dns , http ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.permits("tls") || !f.permits("dns") || !f.permits("http") {
		t.Errorf("whitespace should be tolerated around tokens")
	}
}

func TestParseCheckFilter_BadName(t *testing.T) {
	_, err := parseCheckFilter("tls,notacheck")
	if err == nil {
		t.Fatalf("expected error for unknown check name")
	}
}

func TestParseProfile_Fast(t *testing.T) {
	f, err := parseProfile("fast")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fast: DNS + TCP + TLS + HTTP only.
	for _, name := range []string{"DNS", "TCP", "TLS", "HTTP"} {
		if !f.permits(name) {
			t.Errorf("--profile fast should permit %q", name)
		}
	}
	for _, name := range []string{"Mail", "Reputation", "Path", "Domain", "Delegation"} {
		if f.permits(name) {
			t.Errorf("--profile fast should NOT permit %q", name)
		}
	}
}

func TestParseProfile_Mail(t *testing.T) {
	f, err := parseProfile("mail")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"DNS", "Domain", "TCP", "TLS", "Mail", "Reputation", "IPv6"} {
		if !f.permits(name) {
			t.Errorf("--profile mail should permit %q", name)
		}
	}
	for _, name := range []string{"HTTP", "Security", "Discovery", "Path"} {
		if f.permits(name) {
			t.Errorf("--profile mail should NOT permit %q", name)
		}
	}
}

func TestParseProfile_FullVsParanoid(t *testing.T) {
	full, err := parseProfile("full")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	paranoid, err := parseProfile("paranoid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Full and paranoid both include all default checks. Paranoid
	// additionally includes Ports (which would otherwise be opt-in).
	for _, name := range []string{"DNS", "TLS", "HTTP", "Mail", "Reputation"} {
		if !full.permits(name) || !paranoid.permits(name) {
			t.Errorf("both full and paranoid should permit %q", name)
		}
	}
	if full.permits("Ports") {
		t.Errorf("full should NOT include Ports (user opts in separately)")
	}
	if !paranoid.permits("Ports") {
		t.Errorf("paranoid should include Ports")
	}
}

func TestParseProfile_Unknown(t *testing.T) {
	_, err := parseProfile("notaprofile")
	if err == nil {
		t.Fatalf("expected error for unknown profile name")
	}
}

func TestCheckFilter_NilSafe(t *testing.T) {
	// runAllChecks calls d.filter.permits — must be nil-safe so the
	// default "no filter" case doesn't panic.
	var f *checkFilter
	if !f.permits("anything") {
		t.Errorf("nil filter should permit everything")
	}
	if !f.allowsAll() {
		t.Errorf("nil filter should allowsAll()")
	}
}

func TestParseCheckFilter_AutoAddsDNS(t *testing.T) {
	// Requesting any IP-dependent check (TLS, HTTP, Path, Mail, ...) without
	// explicit DNS should still resolve DNS — otherwise the dependent
	// check skips with an opaque "DNS did not resolve" message that
	// confuses first-time users.
	cases := []struct {
		spec      string
		expectDNS bool
	}{
		{"tls", true},
		{"http", true},
		{"path", true},
		{"mail", true},
		{"ipv6", true},
		{"reputation", true},
		{"tls,http", true},
		{"dns", true},     // explicit dns — already permits
		{"domain", false}, // domain via RDAP doesn't need DNS resolution
		{"delegation", false},
	}
	for _, c := range cases {
		f, err := parseCheckFilter(c.spec)
		if err != nil {
			t.Fatalf("spec %q: parse error %v", c.spec, err)
		}
		got := f.permits("dns")
		if got != c.expectDNS {
			t.Errorf("spec %q: dns permitted=%v want %v", c.spec, got, c.expectDNS)
		}
	}
}

func TestParseCheckFilter_AutoAddsDNS_PreservesOriginals(t *testing.T) {
	// Auto-adding DNS must not remove other entries.
	f, err := parseCheckFilter("tls,http")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TLS", "HTTP", "DNS"} {
		if !f.permits(name) {
			t.Errorf("expected %q to be permitted after auto-add", name)
		}
	}
	if f.permits("Path") {
		t.Errorf("path should not be permitted (was not in spec)")
	}
}
