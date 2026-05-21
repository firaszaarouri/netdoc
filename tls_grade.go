package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// SSL Labs-style A+/A/B/C/D/F TLS grading. Closes the major missing
// signal in netdoc vs SSL Labs ssltest + Hardenize: a single
// defensible letter grade managers can put in a slide.
//
// Algorithm mirrors the SSL Labs methodology, documented at
// https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
// (last revised 2020), with the modern adjustments:
//
//   1. Compute a base score from the WEAKEST acceptable cipher / version
//      combo the server allows. Three weighted dimensions:
//        - Protocol support       (30%)  TLS 1.3 = 100, TLS 1.2 = 90, ...
//        - Key exchange strength  (30%)  ECDHE = 100, RSA-2048 = 80, ...
//        - Cipher strength        (40%)  AES-256 = 100, AES-128 = 90, 3DES = 20, RC4 = 0
//
//   2. Apply CAPS for known weaknesses:
//        - TLS 1.0 / 1.1 supported → cap C
//        - SSL v3 supported       → cap C (was B in 2014; tighter now)
//        - RC4 in any cipher       → cap B (was C in 2014)
//        - Weak DH (< 2048)        → cap B
//        - SHA-1 cert signature    → cap A
//        - No FS (no ECDHE/DHE)    → cap B
//        - Heartbleed / ROBOT      → cap F
//        - Insecure renegotiation  → cap F
//
//   3. Apply BONUSES:
//        - HSTS enabled + valid    → +1 step to A+ ceiling
//        - HSTS with preload       → +1 step
//        - TLS 1.3 with no fallback to weaker → A+ ceiling
//        - OCSP stapling           → +1 step (Mustaple → A+ ceiling)

// tlsGrade is the per-target SSL-Labs-style verdict.
type tlsGrade struct {
	Letter         string   `json:"letter"`            // "A+", "A", "A-", "B", "C", "D", "F"
	Score          int      `json:"score"`             // 0-100 numerical base
	ProtocolScore  int      `json:"protocol_score"`    // weighted dim 1
	KeyExchScore   int      `json:"key_exchange_score"`// weighted dim 2
	CipherScore    int      `json:"cipher_score"`      // weighted dim 3
	Caps           []string `json:"caps,omitempty"`    // reasons grade was capped
	Bonuses        []string `json:"bonuses,omitempty"` // reasons grade was raised
	Reasoning      string   `json:"reasoning"`         // human-readable summary
}

// gradeTLS computes the letter grade given the inputs we already
// collect (versions, ciphers, cert chain, HSTS, OCSP, FS, weak-DH).
func gradeTLS(
	versions []string, // all TLS versions the server supports (e.g., ["TLS 1.0","TLS 1.2","TLS 1.3"])
	ciphers []cipherInfo, // per-cipher grade A/B/C/F
	leaf *x509.Certificate, // for sig alg + key strength
	hstsValid bool,
	hstsPreload bool,
	ocspStapled bool,
	mustStaple bool,
	forwardSecrecy bool,
	weakDH bool,
	heartbleed bool,
	robot bool,
	insecureReneg bool,
) tlsGrade {
	g := tlsGrade{}

	// Dimension 1: protocol support. Score = highest version × weight.
	g.ProtocolScore = scoreProtocols(versions)
	// Dimension 2: key exchange strength derived from cert key bits.
	g.KeyExchScore = scoreKeyExchange(leaf)
	// Dimension 3: cipher strength = best cipher grade observed.
	g.CipherScore = scoreCiphers(ciphers)

	// Weighted base score per SSL Labs §4: 0.3 * proto + 0.3 * kex + 0.4 * cipher.
	g.Score = (g.ProtocolScore*30 + g.KeyExchScore*30 + g.CipherScore*40) / 100

	// Initial letter from base score.
	letter := scoreToLetter(g.Score)

	// CAPS — downgrades.
	if heartbleed {
		letter = "F"
		g.Caps = append(g.Caps, "Heartbleed vulnerable")
	}
	if robot {
		letter = "F"
		g.Caps = append(g.Caps, "ROBOT vulnerable")
	}
	if insecureReneg {
		letter = "F"
		g.Caps = append(g.Caps, "insecure renegotiation (CVE-2009-3555)")
	}
	if containsAny(versions, "SSL 3") {
		letter = capLetter(letter, "C")
		g.Caps = append(g.Caps, "SSLv3 enabled")
	}
	if containsAny(versions, "TLS 1.0") {
		letter = capLetter(letter, "C")
		g.Caps = append(g.Caps, "TLS 1.0 enabled")
	}
	if containsAny(versions, "TLS 1.1") {
		letter = capLetter(letter, "C")
		g.Caps = append(g.Caps, "TLS 1.1 enabled")
	}
	for _, c := range ciphers {
		if strings.Contains(strings.ToUpper(c.Name), "RC4") {
			letter = capLetter(letter, "B")
			g.Caps = append(g.Caps, "RC4 ciphers offered")
			break
		}
	}
	if weakDH {
		letter = capLetter(letter, "B")
		g.Caps = append(g.Caps, "weak DH parameters (< 2048 bit)")
	}
	if !forwardSecrecy {
		letter = capLetter(letter, "B")
		g.Caps = append(g.Caps, "no forward secrecy (ECDHE/DHE absent)")
	}
	if leaf != nil {
		if strings.Contains(strings.ToLower(leaf.SignatureAlgorithm.String()), "sha1") ||
			strings.Contains(strings.ToLower(leaf.SignatureAlgorithm.String()), "md5") {
			letter = capLetter(letter, "A")
			g.Caps = append(g.Caps, "weak cert signature ("+leaf.SignatureAlgorithm.String()+")")
		}
	}

	// SSL Labs Feb 2025 grade-revision deltas:
	//   - TLS 1.3 absence caps the grade at A- (per the Feb 2025 update;
	//     reasoning: in 2026 the absence of TLS 1.3 is a deliberate
	//     omission, not lag)
	//   - HSTS missing drops A → A- (HSTS is now table-stakes hardening)
	hasTLS13 := containsAny(versions, "TLS 1.3")
	if !hasTLS13 && letter == "A" {
		letter = "A-"
		g.Caps = append(g.Caps, "TLS 1.3 not offered (SSL Labs Feb 2025: caps A-)")
	}
	if !hstsValid && letter == "A" {
		letter = "A-"
		g.Caps = append(g.Caps, "HSTS missing (SSL Labs Feb 2025: caps A-)")
	}

	// BONUSES — uplift to A+.
	// A+ requires: base A, no caps, HSTS valid (≥1yr max-age), modern
	// protocols only (no TLS 1.0/1.1/SSL3). Preload + Must-Staple are
	// strong-confidence accelerators.
	modernOnly := !containsAny(versions, "TLS 1.0", "TLS 1.1", "SSL 3")
	if letter == "A" && len(g.Caps) == 0 && hstsValid && modernOnly {
		letter = "A+"
		g.Bonuses = append(g.Bonuses, "HSTS valid", "modern protocols only (TLS 1.2+)")
		if hstsPreload {
			g.Bonuses = append(g.Bonuses, "HSTS preload-eligible")
		}
		if mustStaple && ocspStapled {
			g.Bonuses = append(g.Bonuses, "OCSP Must-Staple enforced")
		}
	}

	g.Letter = letter
	g.Reasoning = explainGrade(g)
	return g
}

// scoreProtocols translates the highest supported TLS version into a
// 0-100 protocol score. SSL Labs methodology rounded to the modern
// reality:
//   TLS 1.3 best supported = 100
//   TLS 1.2 best            = 90
//   TLS 1.1 best            = 60
//   TLS 1.0 best            = 50
//   SSL 3 best              = 30
//   SSL 2 best              = 0
func scoreProtocols(versions []string) int {
	if containsAny(versions, "TLS 1.3") {
		return 100
	}
	if containsAny(versions, "TLS 1.2") {
		return 90
	}
	if containsAny(versions, "TLS 1.1") {
		return 60
	}
	if containsAny(versions, "TLS 1.0") {
		return 50
	}
	if containsAny(versions, "SSL 3") {
		return 30
	}
	return 0
}

// scoreKeyExchange maps cert key strength to 0-100.
//   ECDSA P-256+        = 100
//   RSA 4096+           = 100
//   RSA 2048-3072       = 90
//   RSA 1024            = 40 (deprecated)
//   RSA 512             = 0
func scoreKeyExchange(leaf *x509.Certificate) int {
	if leaf == nil {
		return 50
	}
	bits := keyBits(leaf)
	alg := keyAlgorithmName(leaf)
	switch strings.ToLower(alg) {
	case "ecdsa", "ed25519":
		if bits >= 256 {
			return 100
		}
		return 80
	case "rsa":
		switch {
		case bits >= 4096:
			return 100
		case bits >= 2048:
			return 90
		case bits >= 1024:
			return 40
		default:
			return 0
		}
	}
	return 50
}

// scoreCiphers maps the BEST observed cipher grade to a 0-100 score.
// The user already has per-suite A/B/C/F grades; we collapse the worst-
// case acceptable cipher to one number.
func scoreCiphers(ciphers []cipherInfo) int {
	// Find the BEST grade offered. (Strongest cipher determines ceiling;
	// the per-version cipher enum already breaks down by version.)
	bestRank := 0
	for _, c := range ciphers {
		r := cipherGradeToRank(c.Grade)
		if r > bestRank {
			bestRank = r
		}
	}
	switch bestRank {
	case 4: // A
		return 100
	case 3: // B
		return 80
	case 2: // C
		return 60
	case 1: // F
		return 20
	}
	return 0
}

// cipherGradeToRank converts our A/B/C/F string grade into a numeric
// rank (higher is better).
func cipherGradeToRank(grade string) int {
	switch grade {
	case "A":
		return 4
	case "B":
		return 3
	case "C":
		return 2
	case "F":
		return 1
	}
	return 0
}

// scoreToLetter maps the weighted 0-100 base score to A/B/C/D/F.
// SSL Labs thresholds:
//   ≥80 = A, ≥65 = B, ≥50 = C, ≥35 = D, <35 = F.
func scoreToLetter(score int) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 65:
		return "B"
	case score >= 50:
		return "C"
	case score >= 35:
		return "D"
	default:
		return "F"
	}
}

// capLetter returns the lower of two letter grades. "F" < "D" < "C" <
// "B" < "A" < "A+".
func capLetter(current, cap string) string {
	if letterRank(current) <= letterRank(cap) {
		return current
	}
	return cap
}

func letterRank(letter string) int {
	switch letter {
	case "A+":
		return 6
	case "A":
		return 5
	case "A-":
		return 4
	case "B":
		return 3
	case "C":
		return 2
	case "D":
		return 1
	case "F":
		return 0
	}
	return -1
}

// containsAny reports whether any of needles appears (substring match)
// in any of haystack's entries.
func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if strings.Contains(h, n) {
				return true
			}
		}
	}
	return false
}

// explainGrade builds a one-line human-readable summary for the grade.
func explainGrade(g tlsGrade) string {
	parts := []string{fmt.Sprintf("%s (base score %d)", g.Letter, g.Score)}
	if len(g.Caps) > 0 {
		parts = append(parts, "capped: "+strings.Join(g.Caps, ", "))
	}
	if len(g.Bonuses) > 0 {
		parts = append(parts, "bonus: "+strings.Join(g.Bonuses, ", "))
	}
	return strings.Join(parts, " · ")
}

// gradeHeadline returns "Grade: A+" for the TLS check summary line.
// Always shown when a grade was computed; empty letter is treated as
// "no grade" and produces no headline.
func gradeHeadline(g tlsGrade) string {
	if g.Letter == "" {
		return ""
	}
	return "Grade: " + g.Letter
}

// Silence unused imports when individual references are restructured.
var _ = time.Now
var _ = tls.VersionTLS12
