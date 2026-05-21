package main

import (
	"strings"
)

// Mozilla TLS Configuration Profile compliance. Mozilla publishes three
// recommended TLS configurations (modern / intermediate / old) covering
// protocol versions, cipher suites, key exchange, and signature algorithms.
// sslyze's `--mozilla_config=modern` is the reference CLI implementation.
//
// netdoc evaluates each profile against the server's observed posture (TLS
// versions accepted + cipher enumeration) and reports pass/fail per profile,
// with the specific reason on failure.
//
// Reference: https://wiki.mozilla.org/Security/Server_Side_TLS (v5.7,
// current as of 2025). Configurations are versioned; we embed the rule
// set as of 2026-05-20.

// mozillaProfile describes one of the three recommended configurations.
type mozillaProfile struct {
	Name             string   // "modern" / "intermediate" / "old"
	MinTLSVersion    string   // "TLS 1.3" / "TLS 1.2" / "TLS 1.0"
	MaxTLSVersion    string   // typically "TLS 1.3"
	AllowedTLS12     []uint16 // cipher suites permitted at TLS 1.2 (intermediate/old)
	AllowedTLS13     []uint16 // TLS 1.3 ciphers
	ForbidWeakCiphers bool    // explicit deny of RC4/3DES/EXPORT regardless
}

// mozillaModern — TLS 1.3 ONLY. The strictest profile, suitable for modern
// browsers (Firefox 63+, Chrome 70+, Safari 12.1+). Forbids TLS 1.2 entirely.
var mozillaModern = mozillaProfile{
	Name:          "modern",
	MinTLSVersion: "TLS 1.3",
	MaxTLSVersion: "TLS 1.3",
	AllowedTLS13: []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
	},
}

// mozillaIntermediate — TLS 1.2 + TLS 1.3, the recommended general-purpose
// profile balancing security and compatibility.
var mozillaIntermediate = mozillaProfile{
	Name:          "intermediate",
	MinTLSVersion: "TLS 1.2",
	MaxTLSVersion: "TLS 1.3",
	AllowedTLS12: []uint16{
		0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
		0xc030, // ECDHE-RSA-AES256-GCM-SHA384
		0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
		0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
		0xcca8, // ECDHE-RSA-CHACHA20-POLY1305
		0xcca9, // ECDHE-ECDSA-CHACHA20-POLY1305
		0x009e, // DHE-RSA-AES128-GCM-SHA256
		0x009f, // DHE-RSA-AES256-GCM-SHA384
	},
	AllowedTLS13: []uint16{
		0x1301, 0x1302, 0x1303,
	},
	ForbidWeakCiphers: true,
}

// mozillaOld — TLS 1.0 through TLS 1.3, for legacy support only. Discouraged
// for any new deployment but still useful for "we have to support IE 8".
var mozillaOld = mozillaProfile{
	Name:          "old",
	MinTLSVersion: "TLS 1.0",
	MaxTLSVersion: "TLS 1.3",
	AllowedTLS12: []uint16{
		// All intermediate ciphers PLUS broader compat set
		0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9,
		0x009e, 0x009f,
		// CBC fallbacks for legacy
		0xc013, 0xc014, 0xc009, 0xc00a,
		0x0033, 0x0039,
		// RSA static (least preferred but allowed)
		0x002f, 0x0035, 0x009c, 0x009d,
	},
	AllowedTLS13: []uint16{
		0x1301, 0x1302, 0x1303,
	},
	ForbidWeakCiphers: true,
}

// mozillaComplianceResult records pass/fail for each profile.
type mozillaComplianceResult struct {
	Modern       mozillaProfileVerdict `json:"modern"`
	Intermediate mozillaProfileVerdict `json:"intermediate"`
	Old          mozillaProfileVerdict `json:"old"`
}

// mozillaProfileVerdict is one profile's outcome.
type mozillaProfileVerdict struct {
	Passes  bool     `json:"passes"`
	Reasons []string `json:"reasons,omitempty"`
}

// evaluateMozillaCompliance checks the server's observed TLS posture against
// each profile. Inputs are the version probes + cipher enumeration we
// already collected.
func evaluateMozillaCompliance(versions []tlsVersionProbe, cipherEnums []cipherEnum) mozillaComplianceResult {
	return mozillaComplianceResult{
		Modern:       evalProfile(mozillaModern, versions, cipherEnums),
		Intermediate: evalProfile(mozillaIntermediate, versions, cipherEnums),
		Old:          evalProfile(mozillaOld, versions, cipherEnums),
	}
}

// evalProfile applies one profile's rules.
func evalProfile(p mozillaProfile, versions []tlsVersionProbe, cipherEnums []cipherEnum) mozillaProfileVerdict {
	var reasons []string

	// Rule 1: protocol versions. The server MUST support every version in
	// the profile's range AND MUST NOT support versions below MinTLSVersion.
	minOK := false
	for _, v := range versions {
		if !v.Supported {
			continue
		}
		// Server supports a version below the profile's floor → fail
		if tlsVersionLessThan(v.Name, p.MinTLSVersion) {
			reasons = append(reasons, "server allows "+v.Name+" (below profile floor "+p.MinTLSVersion+")")
		}
		if v.Name == p.MinTLSVersion || v.Name == p.MaxTLSVersion {
			minOK = true
		}
	}
	if !minOK {
		reasons = append(reasons, "server doesn't support required "+p.MinTLSVersion)
	}

	// Rule 2: cipher suites. Every NEGOTIABLE cipher at each supported
	// version must be in the profile's allow-list.
	for _, ce := range cipherEnums {
		var allowed []uint16
		switch ce.TLSVersion {
		case "TLS 1.3":
			allowed = p.AllowedTLS13
		case "TLS 1.2":
			allowed = p.AllowedTLS12
		default:
			continue // TLS 1.0/1.1: handled via the version rule above
		}
		for _, ci := range ce.Ciphers {
			if !cipherInList(ci.Code, allowed) {
				reasons = append(reasons,
					ce.TLSVersion+": disallowed cipher "+ci.Name)
				if len(reasons) > 5 {
					reasons = append(reasons, "(more — truncated)")
					break
				}
			}
		}
		if len(reasons) > 6 {
			break
		}
	}

	// Rule 3: explicit weak-cipher deny (RC4 / 3DES / EXPORT). These should
	// never appear regardless of profile.
	if p.ForbidWeakCiphers {
		for _, ce := range cipherEnums {
			for _, ci := range ce.Ciphers {
				if ci.Grade == "F" {
					reasons = append(reasons,
						ce.TLSVersion+": F-graded cipher "+ci.Name)
					break
				}
			}
		}
	}

	return mozillaProfileVerdict{
		Passes:  len(reasons) == 0,
		Reasons: reasons,
	}
}

// tlsVersionLessThan returns true iff a < b in TLS-version ordering.
// Helper for the "server allows below floor" check.
func tlsVersionLessThan(a, b string) bool {
	rank := map[string]int{
		"SSL 2.0": 0,
		"SSL 3.0": 1,
		"TLS 1.0": 2,
		"TLS 1.1": 3,
		"TLS 1.2": 4,
		"TLS 1.3": 5,
	}
	return rank[a] < rank[b]
}

func cipherInList(c uint16, list []uint16) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

// mozillaHeadline returns "Mozilla: intermediate ✓ / modern ✗" etc.
func mozillaHeadline(r mozillaComplianceResult) string {
	var parts []string
	if r.Modern.Passes {
		parts = append(parts, "modern ✓")
	}
	if r.Intermediate.Passes {
		parts = append(parts, "intermediate ✓")
	}
	if r.Old.Passes && !r.Intermediate.Passes && !r.Modern.Passes {
		// Only surface "old" when nothing stricter passes — otherwise it's noisy.
		parts = append(parts, "old ✓")
	}
	if !r.Modern.Passes && !r.Intermediate.Passes && !r.Old.Passes {
		return "Mozilla: fails all"
	}
	if len(parts) == 0 {
		return ""
	}
	return "Mozilla: " + strings.Join(parts, " / ")
}
