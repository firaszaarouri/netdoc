package main

import (
	"testing"
)

// TestGradeTLS_SSLLabsFeb2025_NoTLS13Caps confirms a TLS 1.2-only
// server is capped at A- per the SSL Labs Feb 2025 revision, not A.
func TestGradeTLS_SSLLabsFeb2025_NoTLS13Caps(t *testing.T) {
	g := gradeTLS(
		[]string{"TLS 1.2"}, // no TLS 1.3
		[]cipherInfo{{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Grade: "A"}},
		nil,  // no leaf
		true, // hstsValid
		false,
		false, false, true, false, false, false, false,
	)
	if g.Letter != "A-" {
		t.Errorf("TLS 1.2-only should cap A-, got %q (caps=%v)", g.Letter, g.Caps)
	}
	wantCap := "TLS 1.3 not offered"
	found := false
	for _, c := range g.Caps {
		if c[:len(wantCap)] == wantCap {
			found = true
		}
	}
	if !found {
		t.Errorf("caps should mention TLS 1.3 absence: %v", g.Caps)
	}
}

// TestGradeTLS_SSLLabsFeb2025_HSTSMissingCaps confirms HSTS-missing
// drops the grade from A to A- per the SSL Labs Feb 2025 revision.
func TestGradeTLS_SSLLabsFeb2025_HSTSMissingCaps(t *testing.T) {
	g := gradeTLS(
		[]string{"TLS 1.3", "TLS 1.2"}, // TLS 1.3 present
		[]cipherInfo{{Name: "TLS_AES_128_GCM_SHA256", Grade: "A"}},
		nil,
		false, // hstsValid = false → cap
		false, false, false, true, false, false, false, false,
	)
	if g.Letter != "A-" {
		t.Errorf("HSTS missing should cap A-, got %q (caps=%v)", g.Letter, g.Caps)
	}
}

// TestGradeTLS_TLS13_HSTS_APlus confirms a fully-modern target with
// HSTS + TLS 1.3 + ECDHE ciphers reaches A+ — the bonuses still work
// after the Feb 2025 cap was added.
func TestGradeTLS_TLS13_HSTS_APlus(t *testing.T) {
	g := gradeTLS(
		[]string{"TLS 1.3", "TLS 1.2"},
		[]cipherInfo{{Name: "TLS_AES_128_GCM_SHA256", Grade: "A"}},
		nil,
		true, // hstsValid
		true, // hstsPreload
		false, false,
		true,  // forwardSecrecy
		false, false, false, false,
	)
	if g.Letter != "A+" {
		t.Errorf("modern A+ candidate should be A+, got %q (caps=%v bonuses=%v)", g.Letter, g.Caps, g.Bonuses)
	}
}
