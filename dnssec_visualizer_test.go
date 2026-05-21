package main

import (
	"strings"
	"testing"
)

// TestRenderDNSSECChain_Validated checks the happy-path layout against
// the cloudflare-shape chain: root → TLD → registrable-domain with a
// signed A leaf. The render should produce branches in tree order with
// ✓ verdicts at every node.
func TestRenderDNSSECChain_Validated(t *testing.T) {
	v := &dnssecValidation{
		Validated: true,
		Levels: []dnssecLevelResult{
			{Zone: ".", Trusted: true, KSKTag: 20326, Algorithm: "RSASHA256"},
			{Zone: "com.", Trusted: true, KSKTag: 19718, Algorithm: "ECDSAP256SHA256", ZSKTags: []uint16{27677}},
			{Zone: "cloudflare.com.", Trusted: true, KSKTag: 2371, Algorithm: "ECDSAP256SHA256", ZSKTags: []uint16{34505}},
		},
		LeafAnswer: &dnssecAnswer{
			Type:     "A",
			Records:  []string{"104.16.132.229", "104.16.133.229"},
			SignedBy: 34505,
			Verified: true,
		},
	}
	out := renderDNSSECChain(v, "cloudflare.com", false)
	wants := []string{
		"DNSSEC chain — cloudflare.com ✓ validated",
		"├─ . (root)",
		"KSK 20326",
		"RSASHA256",
		"matches IANA trust anchor",
		"├─ com.",
		"KSK 19718",
		"ECDSAP256SHA256",
		"ZSKs: 27677",
		"├─ cloudflare.com.",
		"KSK 2371",
		"ZSKs: 34505",
		"└─ A → 104.16.132.229, 104.16.133.229",
		"signed by ZSK 34505",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q\n--- got ---\n%s", w, out)
		}
	}
}

// TestRenderDNSSECChain_Failed confirms the broken-chain layout: the
// validation status header shows ✗ + reason, and the failed level
// surfaces its specific failure mode.
func TestRenderDNSSECChain_Failed(t *testing.T) {
	v := &dnssecValidation{
		Validated: false,
		Reason:    "no DS in parent: NXDOMAIN",
		Levels: []dnssecLevelResult{
			{Zone: ".", Trusted: true, KSKTag: 20326, Algorithm: "RSASHA256"},
			{Zone: "example.", Trusted: false, Reason: "no DS in parent: NXDOMAIN"},
		},
	}
	out := renderDNSSECChain(v, "broken.example", false)
	wants := []string{
		"DNSSEC chain — broken.example ✗ no DS in parent: NXDOMAIN",
		"├─ . (root)",
		"matches IANA trust anchor",
		"└─ example.",
		"✗ no DS in parent: NXDOMAIN",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q\n--- got ---\n%s", w, out)
		}
	}
}

// TestRenderDNSSECChain_NilNoLeaf covers a sec.Chain set but with no
// LeafAnswer (intermediate validation states). The last level must be
// rendered with └─, not ├─.
func TestRenderDNSSECChain_NilNoLeaf(t *testing.T) {
	v := &dnssecValidation{
		Validated: true,
		Levels: []dnssecLevelResult{
			{Zone: ".", Trusted: true, KSKTag: 20326, Algorithm: "RSASHA256"},
			{Zone: "com.", Trusted: true, KSKTag: 19718, Algorithm: "ECDSAP256SHA256"},
		},
	}
	out := renderDNSSECChain(v, "com", false)
	if !strings.Contains(out, "└─ com.") {
		t.Errorf("last level should be rendered with └─, got:\n%s", out)
	}
	if strings.Contains(out, "├─ com.") {
		t.Errorf("last level should not use ├─, got:\n%s", out)
	}
}

// TestRenderDNSSECChain_Color confirms the ANSI escapes appear only
// when color=true. Plain mode should be free of escape codes.
func TestRenderDNSSECChain_Color(t *testing.T) {
	v := &dnssecValidation{
		Validated: true,
		Levels: []dnssecLevelResult{
			{Zone: ".", Trusted: true, KSKTag: 20326, Algorithm: "RSASHA256"},
		},
	}
	plain := renderDNSSECChain(v, "example.com", false)
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("plain mode should not contain ANSI escapes:\n%s", plain)
	}
	colored := renderDNSSECChain(v, "example.com", true)
	if !strings.Contains(colored, "\x1b[32m") {
		t.Errorf("color mode should contain green ANSI escape:\n%s", colored)
	}
}

// TestRenderDNSSECChain_Nil guards against a nil input (e.g. when chain
// validation didn't run because the zone is unsigned).
func TestRenderDNSSECChain_Nil(t *testing.T) {
	if got := renderDNSSECChain(nil, "example.com", false); got != "" {
		t.Errorf("nil chain should render empty, got %q", got)
	}
}
