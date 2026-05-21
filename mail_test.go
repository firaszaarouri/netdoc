package main

import (
	"strings"
	"testing"
)

// Tests for SPF / DMARC parsers and DMARC external-auth helpers
// (RFC 7489 §7.1).

// --- SPF parser tests ---

func TestParseSPF_NotSPF(t *testing.T) {
	if got := parseSPF("v=DMARC1; p=reject"); got != nil {
		t.Errorf("non-SPF TXT should return nil, got %+v", got)
	}
	if got := parseSPF(""); got != nil {
		t.Errorf("empty TXT should return nil, got %+v", got)
	}
}

func TestParseSPF_StrictReject(t *testing.T) {
	p := parseSPF("v=spf1 mx -all")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	if p.All != "-all" {
		t.Errorf("All: got %q want -all", p.All)
	}
	if p.Lookups != 1 {
		t.Errorf("Lookups: got %d want 1 (mx)", p.Lookups)
	}
	if len(p.Issues) > 0 {
		t.Errorf("clean record should have no issues, got %v", p.Issues)
	}
}

func TestParseSPF_PermissiveAll(t *testing.T) {
	p := parseSPF("v=spf1 a mx +all")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "+all") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("+all should flag issue, got Issues=%v", p.Issues)
	}
}

func TestParseSPF_MissingTerminalAll(t *testing.T) {
	p := parseSPF("v=spf1 mx")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "terminal") || strings.Contains(i, "all") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("missing terminal 'all' should flag issue")
	}
}

func TestParseSPF_LookupLimit(t *testing.T) {
	// RFC 7208 §4.6.4: max 10 DNS-lookup mechanisms. We surface a warning
	// at >10.
	mechs := make([]string, 0, 12)
	mechs = append(mechs, "v=spf1")
	for i := 0; i < 11; i++ {
		mechs = append(mechs, "include:_spf"+strings.Repeat("x", i)+".example.com")
	}
	mechs = append(mechs, "-all")
	p := parseSPF(strings.Join(mechs, " "))
	if p == nil {
		t.Fatal("expected non-nil")
	}
	if p.Lookups < 11 {
		t.Errorf("Lookups: got %d want >=11", p.Lookups)
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "10") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("should flag lookup-count issue, got Issues=%v", p.Issues)
	}
}

// --- DMARC parser tests ---

func TestParseDMARC_NotDMARC(t *testing.T) {
	if got := parseDMARC("v=spf1 -all"); got != nil {
		t.Errorf("non-DMARC TXT should return nil")
	}
}

func TestParseDMARC_StrictRejectFull(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:reports@example.com; aspf=s; adkim=s")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	if p.Policy != "reject" {
		t.Errorf("Policy: got %q want reject", p.Policy)
	}
	if p.SubPolicy != "reject" {
		t.Errorf("SubPolicy: got %q want reject", p.SubPolicy)
	}
	if p.Percentage != 100 {
		t.Errorf("Percentage: got %d want 100", p.Percentage)
	}
	if len(p.RUA) != 1 {
		t.Errorf("RUA: got %v want 1 entry", p.RUA)
	}
	if p.AlignDKIM != "s" || p.AlignSPF != "s" {
		t.Errorf("alignment: got dkim=%q spf=%q want s/s", p.AlignDKIM, p.AlignSPF)
	}
	if len(p.Issues) > 0 {
		t.Errorf("clean record should have no issues, got %v", p.Issues)
	}
}

func TestParseDMARC_NoneMonitoring(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=none; rua=mailto:r@example.com")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "p=none") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("p=none should be flagged as monitoring-only")
	}
}

func TestParseDMARC_NoReporting(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=quarantine")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "rua") || strings.Contains(i, "ruf") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("missing rua/ruf should be flagged")
	}
}

func TestParseDMARC_PartialEnforcement(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=reject; pct=50; rua=mailto:r@example.com")
	if p == nil {
		t.Fatal("expected non-nil")
	}
	foundIssue := false
	for _, i := range p.Issues {
		if strings.Contains(i, "50") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("pct=50 should be flagged as partial enforcement")
	}
}

func TestSplitDMARCAddrs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"mailto:a@example.com", []string{"mailto:a@example.com"}},
		{"mailto:a@example.com, mailto:b@example.com", []string{"mailto:a@example.com", "mailto:b@example.com"}},
		{"mailto:a@example.com,,  mailto:b@example.com", []string{"mailto:a@example.com", "mailto:b@example.com"}},
	}
	for _, c := range cases {
		got := splitDMARCAddrs(c.in)
		if len(got) != len(c.want) {
			t.Errorf("in=%q: got %v want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("in=%q [%d]: got %q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// --- DMARC external auth tests (RFC 7489 §7.1) ---

func TestExtractDMARCDestination_Mailto(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"mailto:reports@example.com", "example.com"},
		{"mailto:dmarc@reports.example.org", "reports.example.org"},
		{"MAILTO:user@example.com", "example.com"}, // case-insensitive scheme
		{"mailto:user@example.com!10m", "example.com"}, // size indicator stripped
	}
	for _, c := range cases {
		got := extractDMARCDestination(c.in)
		if got != c.want {
			t.Errorf("in=%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestExtractDMARCDestination_HTTPS(t *testing.T) {
	got := extractDMARCDestination("https://dmarc.example.com/api")
	if got != "dmarc.example.com" {
		t.Errorf("got %q want dmarc.example.com", got)
	}
}

func TestExtractDMARCDestination_Malformed(t *testing.T) {
	// No "@" in mailto: → no destination extractable.
	if got := extractDMARCDestination("mailto:nobody"); got != "" {
		t.Errorf("malformed mailto: got %q want empty", got)
	}
}

func TestSameApex(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com", "example.com", true},
		{"mail.example.com", "example.com", true},
		{"reports.example.com", "billing.example.com", true},
		{"example.com", "example.org", false},
		{"example.com", "evil.com", false},
		{"sub.example.com.", "example.com", true}, // trailing dot tolerated
	}
	for _, c := range cases {
		got := sameApex(c.a, c.b)
		if got != c.want {
			t.Errorf("sameApex(%q,%q): got %v want %v", c.a, c.b, got, c.want)
		}
	}
}
