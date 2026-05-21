package main

import (
	"testing"
)

// gmail-style 2048-bit RSA DKIM record (synthetic but realistic).
// p= is a valid RSA-2048 SubjectPublicKeyInfo in base64.
const dkim2048RSATxt = `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOLVuQNS+u8YkqRf+IGBPdKjBoUaC3kgPaY0OlOJlT8KsxnxFXq21aHkk1XjzeAFV4kQUgK22NjATPDNRgxs3BqWfXucF77G1HvUgIeAa6IM0skfMwBaaJZi+ydz4Bl0kAfPYHQNDxoIuiE/v7FtjCi6FAClFkdYvR7zRtt45sJklI2gnYpUcyN9p2OQ74PJl9P+ZsoZGmWFTbWoxBmRkx4y3KMd7eCV+r/I+QetTo7UN3D4WoTYRwxLI3kxLG+G+gMSObGTcVgyG58Ze3LCMqLuvKWPULNh6c3+u2gflyL3sCt1JTglrFFRWh3DBJ4cUbWMICw6nHJL3SsGNvHzZQIDAQAB`

// Synthetic Ed25519 — 44-char base64 of 32 random bytes (valid length).
const dkimEd25519Txt = `v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`

const dkimWeak512Txt = `v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOnD2ItYWaPa9eqXtBRm5GySgN4WMJp7e75gTb0jHchwhd03ZF7vmZN7Cwiu5kpzbWQAUVZ9aEowdmuFc4LJrtUCAwEAAQ==`

const dkimRevokedTxt = `v=DKIM1; k=rsa; p=`

func TestParseDKIMKey_RSA2048Strong(t *testing.T) {
	info, ok := parseDKIMKey("selector1", dkim2048RSATxt)
	if !ok {
		t.Fatalf("expected strong RSA-2048 to parse OK: %+v", info)
	}
	if info.Algo != "rsa" {
		t.Errorf("algo: got %q want rsa", info.Algo)
	}
	if info.Bits != 2048 {
		t.Errorf("bits: got %d want 2048", info.Bits)
	}
	if !info.Strong {
		t.Errorf("RSA-2048 should be strong: %+v", info)
	}
}

func TestParseDKIMKey_Ed25519(t *testing.T) {
	info, _ := parseDKIMKey("ed", dkimEd25519Txt)
	if info.Algo != "ed25519" {
		t.Errorf("algo: got %q want ed25519", info.Algo)
	}
	if info.Bits != 256 {
		t.Errorf("bits: got %d want 256", info.Bits)
	}
	if !info.Strong {
		t.Errorf("Ed25519 should be strong: %+v", info)
	}
}

func TestParseDKIMKey_Weak512(t *testing.T) {
	info, ok := parseDKIMKey("weak", dkimWeak512Txt)
	if ok {
		t.Error("512-bit RSA should NOT be strong")
	}
	// We attempt to parse; even with a successful parse, Strong must be false.
	if info.Strong {
		t.Errorf("512-bit RSA flagged strong: %+v", info)
	}
}

func TestParseDKIMKey_Revoked(t *testing.T) {
	info, ok := parseDKIMKey("revoked", dkimRevokedTxt)
	if ok {
		t.Error("revoked selector (p= empty) should NOT parse strong")
	}
	if info.Reason == "" {
		t.Errorf("expected reason for revoked selector: %+v", info)
	}
}

func TestParseDKIMTags(t *testing.T) {
	tags := parseDKIMTags("v=DKIM1; k=rsa; p=ABCD; h=sha256; n=Notes here")
	want := map[string]string{
		"v": "DKIM1",
		"k": "rsa",
		"p": "ABCD",
		"h": "sha256",
		"n": "Notes here",
	}
	for k, v := range want {
		if tags[k] != v {
			t.Errorf("tag %q: got %q want %q", k, tags[k], v)
		}
	}
}

func TestDKIMKeyHeadline(t *testing.T) {
	if got := dkimKeyHeadline(nil); got != "" {
		t.Errorf("nil keys should return empty headline, got %q", got)
	}
	keys := []dkimKeyInfo{
		{Selector: "s1", Strong: true},
		{Selector: "s2", Strong: true},
	}
	if got := dkimKeyHeadline(keys); got != "DKIM keys ✓ all strong" {
		t.Errorf("all-strong headline wrong: %q", got)
	}
	mixed := []dkimKeyInfo{
		{Selector: "s1", Strong: true},
		{Selector: "s2", Strong: false},
	}
	got := dkimKeyHeadline(mixed)
	if got != "DKIM keys 1 strong, 1 weak" {
		t.Errorf("mixed headline wrong: %q", got)
	}
}

func TestMXDANEHeadline_AllCompliant(t *testing.T) {
	results := []mxDANEResult{
		{MXHost: "mx1.example.com", Found: true, HasDANEEE: true, SMTPCompliant: true},
		{MXHost: "mx2.example.com", Found: true, HasDANETA: true, SMTPCompliant: true},
	}
	if got := mxDANEHeadline(results); got != "DANE-MX ✓ all" {
		t.Errorf("all-compliant headline wrong: %q", got)
	}
}

func TestMXDANEHeadline_None(t *testing.T) {
	results := []mxDANEResult{
		{MXHost: "mx1.example.com", Found: false},
		{MXHost: "mx2.example.com", Found: false},
	}
	if got := mxDANEHeadline(results); got != "DANE-MX: none" {
		t.Errorf("none headline wrong: %q", got)
	}
}

func TestMXIPv6Headline_AllPresent(t *testing.T) {
	results := []mxIPv6Result{
		{MXHost: "mx1.example.com", HasAAAA: true},
		{MXHost: "mx2.example.com", HasAAAA: true},
	}
	if got := mxIPv6Headline(results); got != "IPv6-MX ✓ all" {
		t.Errorf("all-present headline wrong: %q", got)
	}
}

func TestMXIPv6Headline_Partial(t *testing.T) {
	results := []mxIPv6Result{
		{MXHost: "mx1.example.com", HasAAAA: true},
		{MXHost: "mx2.example.com", HasAAAA: false},
		{MXHost: "mx3.example.com", HasAAAA: false},
	}
	if got := mxIPv6Headline(results); got != "IPv6-MX 1/3" {
		t.Errorf("partial headline wrong: %q", got)
	}
}
