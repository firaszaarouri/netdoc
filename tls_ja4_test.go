package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Tests for JA4S fingerprint helpers. Pure-function helpers are
// deterministic so we can pin every component against expected output.

func TestJA4VersionString(t *testing.T) {
	cases := []struct {
		ver  uint16
		want string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0200, "s2"},
		{0x9999, "00"},
	}
	for _, c := range cases {
		got := ja4VersionString(c.ver)
		if got != c.want {
			t.Errorf("ja4VersionString(0x%04x): got %q want %q", c.ver, got, c.want)
		}
	}
}

func TestJA4ALPNComponent(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"", "00"},
		{"h2", "h2"},
		{"h3", "h3"},
		{"http/1.1", "h1"},
		{"http/1.0", "h0"},
		{"acme-tls/1", "a1"},      // first + last
		{"smb", "sb"},             // first + last
		{"a", "aa"},               // 1-char doubled
	}
	for _, c := range cases {
		got := ja4ALPNComponent(c.alpn)
		if got != c.want {
			t.Errorf("ja4ALPNComponent(%q): got %q want %q", c.alpn, got, c.want)
		}
	}
}

func TestFmtTwoDigit(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "00"},
		{1, "01"},
		{9, "09"},
		{10, "10"},
		{99, "99"},
		{100, "99"}, // caps at 99
		{-5, "00"},  // negative → 0
	}
	for _, c := range cases {
		got := fmtTwoDigit(c.n)
		if got != c.want {
			t.Errorf("fmtTwoDigit(%d): got %q want %q", c.n, got, c.want)
		}
	}
}

func TestSHA256_12(t *testing.T) {
	// Pin against the canonical SHA-256 of empty string truncated to 12 chars.
	emptyHash := sha256.Sum256([]byte(""))
	want := hex.EncodeToString(emptyHash[:])[:12]
	if got := sha256_12(""); got != want {
		t.Errorf("sha256_12(\"\"): got %q want %q", got, want)
	}
	// "abc" → SHA-256 starts with ba7816bf8f01...
	got := sha256_12("abc")
	if got != "ba7816bf8f01" {
		t.Errorf("sha256_12(\"abc\"): got %q want ba7816bf8f01", got)
	}
}

func TestIsGREASE(t *testing.T) {
	// GREASE values (RFC 8701) follow the pattern 0x?A?A where both bytes
	// are equal and the low nibble of each is 0xa.
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("0x%04x should be detected as GREASE", v)
		}
	}
	nonGreaseValues := []uint16{
		0x0000, 0x0301, 0x0303, 0x0304, // TLS versions
		0x1301, 0x1302, 0x1303, // TLS 1.3 cipher suites
		0x00ff,         // empty renegotiation_info
		0xc02f, 0xc02b, // ECDHE cipher suites
		0x1010, // looks like GREASE pattern but low nibble is 0, not a
	}
	for _, v := range nonGreaseValues {
		if isGREASE(v) {
			t.Errorf("0x%04x should NOT be GREASE", v)
		}
	}
}

func TestJA4Headline_EmptyJA4S(t *testing.T) {
	if got := ja4Headline(ja4Result{}); got != "" {
		t.Errorf("empty JA4Result should produce empty headline, got %q", got)
	}
}

func TestJA4Headline_TruncatesLongFingerprint(t *testing.T) {
	r := ja4Result{JA4S: "t130200_1301_thelongtailistruncatedinheadline"}
	got := ja4Headline(r)
	if got == "" {
		t.Errorf("non-empty JA4S should produce non-empty headline")
	}
	// Should truncate with ellipsis.
	if len(got) > 30 {
		t.Errorf("headline too long: %q", got)
	}
}
