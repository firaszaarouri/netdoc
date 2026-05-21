package main

import (
	"testing"
)

// TestCipherRegistry_Size guards against accidental wipe-out and
// validates the catalog is comprehensive enough to claim parity with
// testssl's per-cipher enumeration scope.
func TestCipherRegistry_Size(t *testing.T) {
	if len(cipherRegistry) < 150 {
		t.Errorf("registry shrunk below 150 entries: got %d", len(cipherRegistry))
	}
}

// TestCipherRegistry_Integrity confirms every entry has a name, family,
// and severity — the metadata the --each-cipher reporter needs.
func TestCipherRegistry_Integrity(t *testing.T) {
	for _, c := range cipherRegistry {
		if c.Code == 0 && c.Name != "TLS_NULL_WITH_NULL_NULL" {
			t.Errorf("non-NULL_NULL entry has Code=0: %+v", c)
		}
		if c.Name == "" {
			t.Errorf("entry has no Name: %+v", c)
		}
		if c.Family == "" {
			t.Errorf("entry has no Family: %+v", c)
		}
		if c.Severity == "" {
			t.Errorf("entry has no Severity: %+v", c)
		}
	}
}

// TestCipherRegistry_ByCode covers the lookup helper used by the
// --each-cipher reporter to label accepted ciphers.
func TestCipherRegistry_ByCode(t *testing.T) {
	cases := []struct {
		code uint16
		want string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
		{0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT"},
	}
	for _, c := range cases {
		spec := cipherRegistryByCode(c.code)
		if spec == nil {
			t.Errorf("missing registry entry for 0x%04x", c.code)
			continue
		}
		if spec.Name != c.want {
			t.Errorf("0x%04x: got %q want %q", c.code, spec.Name, c.want)
		}
	}
	if cipherRegistryByCode(0xffff) != nil {
		t.Error("unknown codepoint should return nil")
	}
}

// TestCipherRegistry_AllCodesUnique ensures the deduplication helper
// produces no duplicate codepoints — the elimination algorithm depends
// on it.
func TestCipherRegistry_AllCodesUnique(t *testing.T) {
	codes := cipherRegistryAllCodes()
	seen := map[uint16]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate codepoint in cipherRegistryAllCodes: 0x%04x", c)
		}
		seen[c] = true
	}
}

// TestSummarizeEachCipher covers the severity counter the renderer uses.
func TestSummarizeEachCipher(t *testing.T) {
	rows := []eachCipherResult{
		{Code: 0x0005, Severity: "broken"},
		{Code: 0x000a, Severity: "weak"},
		{Code: 0x0080, Severity: "policy"},
		{Code: 0xc02f, Severity: "modern"},
		{Code: 0xc0a4, Severity: "info"},
		{Code: 0x1301, Severity: "modern"},
		{Code: 0xffff, Severity: ""},
	}
	s := summarizeEachCipher(rows)
	if s.Total != 7 {
		t.Errorf("total: got %d want 7", s.Total)
	}
	if s.Broken != 1 || s.Weak != 1 || s.Policy != 1 || s.Modern != 2 || s.Info != 1 || s.Unknown != 1 {
		t.Errorf("counts wrong: %+v", s)
	}
}

// TestRemoveCipherCode covers the elimination-loop helper that drops
// the picked cipher from the remaining set.
func TestRemoveCipherCode(t *testing.T) {
	codes := []uint16{0x1301, 0xc02f, 0x0005, 0x0080}
	out := removeCipherCode(codes, 0xc02f)
	if len(out) != 3 {
		t.Errorf("expected 3 remaining, got %d (%v)", len(out), out)
	}
	for _, c := range out {
		if c == 0xc02f {
			t.Errorf("0xc02f should have been removed, but it's still there")
		}
	}
	// Removing a non-existent code returns the same set.
	out2 := removeCipherCode(out, 0xffff)
	if len(out2) != len(out) {
		t.Errorf("removing non-existent code changed the set")
	}
}
