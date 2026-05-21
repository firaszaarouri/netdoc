package main

import (
	"strings"
	"testing"
)

// Tests for DNS-layer helpers and parsers.

// --- EDE catalog tests ---

func TestDescribeEDE_KnownCodes(t *testing.T) {
	cases := []struct {
		code   uint16
		wantIn string
	}{
		{0, "Other Error"},
		{6, "Bogus"},
		{15, "Blocked"},
		{19, "Stale NXDOMAIN"},
		{26, "Too Early"},
		{29, "Synthesized"},
	}
	for _, c := range cases {
		got := describeEDE(c.code, "")
		if !strings.Contains(got, c.wantIn) {
			t.Errorf("code %d: got %q, want substring %q", c.code, got, c.wantIn)
		}
	}
}

func TestDescribeEDE_UnknownCode(t *testing.T) {
	got := describeEDE(9999, "")
	if !strings.Contains(got, "9999") {
		t.Errorf("unknown code should include the number, got %q", got)
	}
}

func TestDescribeEDE_WithExtraText(t *testing.T) {
	got := describeEDE(6, "validation failed: NSEC3 chain broken")
	if !strings.Contains(got, "Bogus") {
		t.Errorf("missing base description, got %q", got)
	}
	if !strings.Contains(got, "NSEC3 chain broken") {
		t.Errorf("missing extra text, got %q", got)
	}
}

func TestEDECoverage_RFC8914Range(t *testing.T) {
	// RFC 8914 defines codes 0-29 (as of 2024 IANA registry update).
	// Verify our table covers every assignment. Future drift will fail
	// this test and prompt an update.
	for i := uint16(0); i <= 29; i++ {
		if _, ok := edeCodes[i]; !ok {
			t.Errorf("EDE code %d unassigned in our table — refresh from IANA", i)
		}
	}
}

func TestUint16Str_Roundtrip(t *testing.T) {
	cases := map[uint16]string{
		0:     "0",
		1:     "1",
		29:    "29",
		255:   "255",
		1234:  "1234",
		65535: "65535",
	}
	for v, want := range cases {
		if got := uint16str(v); got != want {
			t.Errorf("uint16str(%d): got %q want %q", v, got, want)
		}
	}
}

// --- dnsTransport parser tests ---

func TestParseDNSTransport_System(t *testing.T) {
	for _, spec := range []string{"", "system"} {
		tr, err := parseDNSTransport(spec)
		if err != nil {
			t.Errorf("spec %q: unexpected error %v", spec, err)
		}
		if tr != nil {
			t.Errorf("spec %q: expected nil transport (system resolver), got %+v", spec, tr)
		}
	}
}

func TestParseDNSTransport_UDPDefault(t *testing.T) {
	tr, err := parseDNSTransport("udp")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode != "udp" || tr.Server != "1.1.1.1:53" {
		t.Errorf("got %+v want udp:1.1.1.1:53", tr)
	}
}

func TestParseDNSTransport_DoTWithExplicitServer(t *testing.T) {
	tr, err := parseDNSTransport("dot:9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode != "dot" || tr.Server != "9.9.9.9:853" {
		t.Errorf("got %+v want dot://9.9.9.9:853", tr)
	}
}

func TestParseDNSTransport_DoTWithPort(t *testing.T) {
	tr, err := parseDNSTransport("dot:9.9.9.9:8530")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Server != "9.9.9.9:8530" {
		t.Errorf("explicit port should be preserved, got %q", tr.Server)
	}
}

func TestParseDNSTransport_DoHFullURL(t *testing.T) {
	tr, err := parseDNSTransport("doh:https://cloudflare-dns.com/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode != "doh" {
		t.Errorf("mode: got %q want doh", tr.Mode)
	}
	if !strings.HasPrefix(tr.Server, "https://") {
		t.Errorf("DoH server should be a URL, got %q", tr.Server)
	}
}

func TestParseDNSTransport_DoHDefault(t *testing.T) {
	tr, err := parseDNSTransport("doh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tr.Server, "cloudflare-dns.com") {
		t.Errorf("default DoH should be Cloudflare, got %q", tr.Server)
	}
}

func TestParseDNSTransport_DoQDefault(t *testing.T) {
	tr, err := parseDNSTransport("doq")
	if err != nil {
		t.Fatal(err)
	}
	// Default DoQ resolver should be Quad9 per the v1.x reliability rationale
	// (Cloudflare DoQ is flaky on some networks).
	if !strings.Contains(tr.Server, "quad9") {
		t.Errorf("default DoQ should be Quad9, got %q", tr.Server)
	}
}

func TestParseDNSTransport_DoQCustom(t *testing.T) {
	tr, err := parseDNSTransport("doq:dns.adguard-dns.com")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode != "doq" || tr.Server != "dns.adguard-dns.com:853" {
		t.Errorf("got %+v want doq:dns.adguard-dns.com:853", tr)
	}
}

func TestParseDNSTransport_Unknown(t *testing.T) {
	_, err := parseDNSTransport("smtp:mail.example.com")
	if err == nil {
		t.Errorf("expected error for unknown transport")
	}
}

func TestDNSTransport_String(t *testing.T) {
	cases := []struct {
		tr   *dnsTransport
		want string
	}{
		{nil, "udp:1.1.1.1:53"},
		{&dnsTransport{Mode: "dot", Server: "9.9.9.9:853"}, "dot://9.9.9.9:853"},
		{&dnsTransport{Mode: "doq", Server: "dns.quad9.net:853"}, "doq://dns.quad9.net:853"},
	}
	for _, c := range cases {
		if got := c.tr.String(); got != c.want {
			t.Errorf("String(%+v): got %q want %q", c.tr, got, c.want)
		}
	}
}
