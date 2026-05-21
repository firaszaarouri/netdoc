package main

import (
	"strings"
	"testing"
	"time"
)

// Unit tests for SMB2 helpers. The full TCP probe requires a live
// SMB2 server; we focus on the deterministic primitives that need
// pinning: dialect naming, signing posture, GUID formatting,
// FILETIME → time.Time conversion.

func TestSMB2DialectName(t *testing.T) {
	cases := []struct {
		dialect uint16
		want    string
	}{
		{0x0202, "2.0.2 (Vista / 2008)"},
		{0x0210, "2.1 (Win7 / 2008 R2)"},
		{0x0300, "3.0 (Win8 / 2012)"},
		{0x0302, "3.0.2 (8.1 / 2012 R2)"},
		{0x0311, "3.1.1 (Win10 / 2016+)"},
		{0x9999, "0x9999"},
	}
	for _, c := range cases {
		if got := smb2DialectName(c.dialect); got != c.want {
			t.Errorf("dialect 0x%04x: got %q want %q", c.dialect, got, c.want)
		}
	}
}

func TestSMB2SigningPosture(t *testing.T) {
	cases := []struct {
		mode uint16
		want string
	}{
		{0x00, "disabled"},
		{0x01, "enabled"},
		{0x02, "required"},
		{0x03, "required"}, // both bits set → still required (higher priority)
	}
	for _, c := range cases {
		if got := smb2SigningPosture(c.mode); got != c.want {
			t.Errorf("mode 0x%02x: got %q want %q", c.mode, got, c.want)
		}
	}
}

func TestFormatGUID(t *testing.T) {
	// Microsoft GUID format with little-endian first three groups.
	// Standard test vector: bytes 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00
	// Should format as: 44332211-6655-8877-99aa-bbccddeeff00
	in := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	want := "44332211-6655-8877-99aa-bbccddeeff00"
	if got := formatGUID(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestFormatGUID_WrongLength(t *testing.T) {
	if got := formatGUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("short input should return empty string, got %q", got)
	}
}

func TestFiletimeToTime(t *testing.T) {
	// FILETIME for 1970-01-01 00:00:00 UTC = 116444736000000000
	ft := uint64(116444736000000000)
	tm := filetimeToTime(ft)
	if tm.Unix() != 0 {
		t.Errorf("FILETIME unix epoch: got %v want 1970-01-01 UTC", tm)
	}

	// FILETIME for 2020-01-01 00:00:00 UTC.
	// 50 years × 365.25 days × 86400 s × 1e7 ticks/s + epoch offset
	// ≈ 132223104000000000
	ft2 := uint64(132223104000000000)
	tm2 := filetimeToTime(ft2)
	if tm2.Year() != 2020 {
		t.Errorf("FILETIME 2020-01-01: got year %d want 2020", tm2.Year())
	}
}

func TestFiletimeToTime_BelowEpoch(t *testing.T) {
	// Values below the Windows-to-Unix epoch should return zero Time.
	tm := filetimeToTime(1000)
	if !tm.IsZero() {
		t.Errorf("below-epoch should be zero time, got %v", tm)
	}
}

func TestProbeSMB2_NoServer(t *testing.T) {
	// Sanity: probing a closed port returns empty serviceInfo without
	// panic. Use a port that's reliably refused on most networks.
	info := probeSMB2("127.0.0.1:1", "", 500*time.Millisecond)
	if info.Product != "" {
		t.Errorf("closed port should return empty serviceInfo, got Product=%q", info.Product)
	}
	if info.Banner != "" {
		t.Errorf("closed port should return empty Banner, got %q", info.Banner)
	}
}

func TestRDPProtocolName(t *testing.T) {
	cases := []struct {
		code uint32
		want string
	}{
		{0x00, "RDP (legacy)"},
		{0x01, "TLS"},
		{0x02, "CredSSP/NLA"},
		{0x03, "TLS+CredSSP/NLA"},
		{0x0b, "TLS+CredSSP/NLA+CredSSP-EX"},
	}
	for _, c := range cases {
		got := rdpProtocolName(c.code)
		if got != c.want {
			t.Errorf("0x%02x: got %q want %q", c.code, got, c.want)
		}
	}
}

func TestRDPFailureName(t *testing.T) {
	if !strings.Contains(rdpFailureName(1), "SSL_REQUIRED") {
		t.Errorf("code 1 should mention SSL_REQUIRED, got %q", rdpFailureName(1))
	}
	if rdpFailureName(999) != "unknown" {
		t.Errorf("unknown code should return %q, got %q", "unknown", rdpFailureName(999))
	}
}
