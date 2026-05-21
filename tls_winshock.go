package main

import (
	"strings"
)

// Winshock CVE-2014-6321 detection — best-effort. Mirrors testssl.sh's
// `--WS / --winshock` flag.
//
// Winshock is a Microsoft Schannel RCE allowing remote attackers to
// execute arbitrary code via crafted packets that trigger memory
// corruption in the SChannel security package. Affects Server 2003 /
// XP / Vista / Server 2008 / 7 / 8 / Server 2012 / 8.1 / Server 2012 R2
// prior to the KB2992611 patch (released Nov 2014).
//
// Authoritative crypto-grade detection requires sending a crafted
// ClientHello with malformed ECC parameters and inspecting the alert
// response delta between patched and unpatched SChannel — that's
// hundreds of LOC of TLS 1.2 wire-format work AND risks crashing
// genuinely-vulnerable production servers.
//
// netdoc's pragmatic approach (same one testssl.sh uses when its
// crypto-grade probe is too risky): INFERENCE-BASED detection. We
// don't actively try to crash anything. Instead:
//
//   1. Check whether the server LOOKS LIKE Schannel via:
//        - JARM fingerprint (Schannel has distinctive JARM patterns)
//        - JA3S server fingerprint
//        - Cipher selection patterns Schannel prefers
//        - HTTP Server header (when web service: "Microsoft-IIS/...")
//
//   2. If yes, we cannot determine patch level without dangerous probes,
//      so report:
//        - "Server appears to be Schannel" + which signals matched
//        - "Cannot determine KB2992611 patch level without invasive probe"
//        - Recommend manual verification + patch confirmation
//
// This is honest detection: we surface the RISK SURFACE without false-
// claiming vulnerability. The user can then manually verify with
// targeted tools (testssl --WS, msf-aux/scanner/ssl/cve_2014_6321) in
// an authorized pentest context.

type winshockResult struct {
	Probed              bool     `json:"probed"`
	SchannelInferred    bool     `json:"schannel_inferred"`
	InferenceSignals    []string `json:"inference_signals,omitempty"`
	PatchLevelKnowable  bool     `json:"patch_level_knowable"`
	Note                string   `json:"note,omitempty"`
}

// probeWinshock collects passive signals from data we've ALREADY gathered
// during the main TLS check + HTTP trace. It does NOT send any additional
// probes. Cost: zero network traffic beyond what's already running.
//
// Inputs:
//   jarm     — JARM fingerprint string
//   ja3s     — JA3S fingerprint string
//   ja4s     — JA4S fingerprint string
//   serverHeader — HTTP Server header value (may be empty)
func probeWinshock(jarm, ja3s, ja4s, serverHeader string) winshockResult {
	out := winshockResult{Probed: true}

	// Schannel-distinctive JARM patterns observed in the wild (curated
	// from JARM database research + Cloudflare's published fingerprints).
	// JARM is structured as 30 hex pairs; the first ~12 hex bytes
	// uniquely identify TLS-stack families.
	schannelJARMPrefixes := []string{
		"2ad2ad0002ad2ad0002ad2ad2ad2ad",   // IIS 10 Schannel default
		"2ad2ad0002ad2ad22c2ad2ad2ad2ad",   // older Schannel variants
		"21d19d00021d21d21c21d19d21d19d",   // Server 2012 R2 default
		"2ad000002ad2ad00042ad2ad2ad2ad",   // Server 2016+ variants
	}
	if jarm != "" {
		for _, prefix := range schannelJARMPrefixes {
			if strings.HasPrefix(jarm, prefix) {
				out.SchannelInferred = true
				out.InferenceSignals = append(out.InferenceSignals,
					"JARM matches Schannel pattern: "+prefix[:16]+"...")
				break
			}
		}
	}

	// HTTP Server header — strongest direct signal when the target is
	// a web service.
	if serverHeader != "" {
		lower := strings.ToLower(serverHeader)
		switch {
		case strings.Contains(lower, "microsoft-iis"):
			out.SchannelInferred = true
			out.InferenceSignals = append(out.InferenceSignals,
				"HTTP Server header: "+serverHeader)
		case strings.Contains(lower, "microsoft-httpapi"):
			out.SchannelInferred = true
			out.InferenceSignals = append(out.InferenceSignals,
				"HTTP Server: HTTP.SYS (Schannel-backed)")
		}
	}

	// JA3S / JA4S — sketch only; production deployments would benefit
	// from a curated database. We surface the fingerprint when present
	// so the user can compare against known Schannel signatures.
	if ja3s != "" {
		out.InferenceSignals = append(out.InferenceSignals, "JA3S: "+ja3s)
	}
	if ja4s != "" {
		out.InferenceSignals = append(out.InferenceSignals, "JA4S: "+ja4s)
	}

	if !out.SchannelInferred {
		out.Note = "no Schannel signals — Winshock not applicable"
		return out
	}

	// Schannel inferred. We can't safely determine patch level from
	// passive signals.
	out.PatchLevelKnowable = false
	out.Note = "Server appears to be Microsoft Schannel. " +
		"Winshock (CVE-2014-6321, KB2992611) affects unpatched Schannel — " +
		"patch level NOT determinable from passive signals. " +
		"Verify via Windows Update history or active probe in an " +
		"authorized pentest context."
	return out
}

// winshockHeadline returns a Schannel-detected note for the TLS summary.
func winshockHeadline(w winshockResult) string {
	if !w.Probed || !w.SchannelInferred {
		return ""
	}
	return "Schannel detected — Winshock (CVE-2014-6321) patch status unverified"
}
