package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// Distrusted-CA detection. Major browser root programs have publicly
// distrusted specific CAs over the years for issuing the equivalent of
// broken certs, mis-issuance, or audit failures. A cert chain that
// includes any of these issuers — even if technically valid by Go's
// system-roots verifier — will be rejected by modern browsers.
//
// netdoc detects via TWO signals layered together:
//
//   1. Issuer Subject DN matching (PRIMARY, verifiable): canonicalised
//      issuer-name strings of distrusted CAs. Any cert in the chain
//      whose Issuer matches the well-known name is flagged. This signal
//      is verifiable from public records (Mozilla CA program, Apple
//      distrust list, Chrome CRLSets) and cannot be spoofed without
//      reissuing the cert under a different CA.
//
//   2. SHA-256 fingerprint matching (SECONDARY): exact match of the
//      DER-encoded cert against a hash. Stronger signal than DN match,
//      but we maintain a curated list (not yet authoritatively verified
//      end-to-end). When a fingerprint hits, we surface it with HIGH
//      confidence; when only a DN matches, MEDIUM confidence.
//
// References:
//   Mozilla CA program: https://wiki.mozilla.org/CA/Additional_Trust_Changes
//   Apple distrust:     https://support.apple.com/en-us/HT212865
//   Chrome CRLSets:     https://www.chromium.org/Home/chromium-security/crlsets/

// distrustedRoot describes one known-bad root CA.
type distrustedRoot struct {
	IssuerDN          string   // canonical Issuer Subject DN
	FingerprintSHA256 string   // 64-char lowercase hex of DER bytes (no colons) — empty if unverified
	CommonName        string   // human-friendly label
	Reason            string
	DistrustedBy      []string // "Mozilla", "Chrome", "Apple", "Microsoft", "Java"
	Since             string   // ISO-8601 date
}

// distrustedRootDB is the curated list. Each entry is verifiable from
// public sources — the CommonName + Reason + DistrustedBy fields are
// from authoritative records; FingerprintSHA256 is informational and
// may be partial until we verify against authoritative cert bytes.
var distrustedRootDB = []distrustedRoot{
	// ===== Verified fingerprints from Mozilla NSS certdata.txt (CKA_NSS_SERVER_DISTRUST_AFTER) =====
	{
		CommonName:        "Entrust Root Certification Authority",
		IssuerDN:          "entrust root certification authority",
		FingerprintSHA256: "73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c",
		Reason:            "Entrust distrust 2024 — operational failures, audit issues",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "Entrust Root Certification Authority - G2",
		IssuerDN:          "entrust root certification authority - g2",
		FingerprintSHA256: "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339",
		Reason:            "Entrust G2 distrust 2024",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "Entrust Root Certification Authority - EC1",
		IssuerDN:          "entrust root certification authority - ec1",
		FingerprintSHA256: "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5",
		Reason:            "Entrust EC1 distrust 2024",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "Entrust.net Premium 2048 Secure Server CA",
		IssuerDN:          "entrust.net certification authority (2048)",
		FingerprintSHA256: "6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177",
		Reason:            "Entrust 2048 distrust 2024",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "ePKI Root Certification Authority",
		IssuerDN:          "epki root certification authority",
		FingerprintSHA256: "c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5",
		Reason:            "Chunghwa Telecom ePKI Root distrust — operational issues",
		DistrustedBy:      []string{"Mozilla"},
		Since:             "2024-06-30",
	},
	// ===== Historical distrusts (removed from current trust stores) =====
	// These CAs were REMOVED from Mozilla NSS entirely after their distrust
	// events, so their cert bytes aren't in modern certdata.txt. We match
	// by Issuer Subject DN (verifiable from historical records) — the
	// fingerprint slot is left empty rather than hard-coding unverified
	// hex. A chain that includes these issuers is rejected by every
	// modern browser; netdoc surfaces the distrust as a HIGH-severity
	// finding via DN match alone.
	{
		CommonName:        "WoSign CA Free SSL Certificate G2",
		IssuerDN:          "wosign ca free ssl certificate g2",
		Reason:            "mis-issuance, backdated SHA-1 certs (2016)",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2017-09-01",
	},
	{
		CommonName:        "WoSign CA Free SSL Certificate G3",
		IssuerDN:          "wosign ca free ssl certificate g3",
		Reason:            "WoSign trust chain — distrusted with G2",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2017-09-01",
	},
	{
		CommonName:        "Certification Authority of WoSign",
		IssuerDN:          "certification authority of wosign",
		Reason:            "WoSign trust chain — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2017-09-01",
	},
	{
		CommonName:        "StartCom Certification Authority",
		IssuerDN:          "startcom certification authority",
		Reason:            "WoSign affiliate; same mis-issuance",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2017-09-01",
	},
	{
		CommonName:        "StartCom Certification Authority G2",
		IssuerDN:          "startcom certification authority g2",
		Reason:            "WoSign affiliate G2 — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2017-09-01",
	},
	{
		CommonName:        "Symantec Class 3 Public Primary Certification Authority - G6",
		IssuerDN:          "symantec class 3 public primary certification authority - g6",
		Reason:            "Symantec-issued cert distrust (post-Google audit)",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "Symantec Class 3 Public Primary Certification Authority - G4",
		IssuerDN:          "symantec class 3 public primary certification authority - g4",
		Reason:            "Symantec distrust event",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "GeoTrust Primary Certification Authority",
		IssuerDN:          "geotrust primary certification authority",
		Reason:            "Symantec subsidiary — same distrust",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "GeoTrust Primary Certification Authority - G3",
		IssuerDN:          "geotrust primary certification authority - g3",
		Reason:            "Symantec subsidiary G3 — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "GeoTrust Global CA",
		IssuerDN:          "geotrust global ca",
		Reason:            "Symantec subsidiary — same distrust",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "thawte Primary Root CA",
		IssuerDN:          "thawte primary root ca",
		Reason:            "Symantec subsidiary thawte — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "thawte Primary Root CA - G2",
		IssuerDN:          "thawte primary root ca - g2",
		Reason:            "Symantec subsidiary thawte G2 — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "thawte Primary Root CA - G3",
		IssuerDN:          "thawte primary root ca - g3",
		Reason:            "Symantec subsidiary thawte G3 — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "VeriSign Class 3 Public Primary CA - G4",
		IssuerDN:          "verisign class 3 public primary certification authority - g4",
		Reason:            "Symantec/VeriSign — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "VeriSign Class 3 Public Primary CA - G5",
		IssuerDN:          "verisign class 3 public primary certification authority - g5",
		Reason:            "Symantec/VeriSign G5 — distrusted",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2018-04-01",
	},
	{
		CommonName:        "CNNIC ROOT",
		IssuerDN:          "cnnic root",
		Reason:            "MCS Holdings unauthorized intermediate (2015)",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2015-04-01",
	},
	{
		CommonName:        "China Internet Network Information Center EV Certificates Root",
		IssuerDN:          "china internet network information center ev certificates root",
		Reason:            "CNNIC EV root — distrusted post-2015",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2015-04-01",
	},
	{
		CommonName:        "TURKTRUST Elektronik Sertifika Hizmet Sağlayıcısı",
		IssuerDN:          "türktrust elektronik sertifika hizmet sağlayıcısı",
		Reason:            "fraudulent *.google.com certificate (2013)",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Microsoft"},
		Since:             "2013-01-01",
	},
	{
		CommonName:        "DigiNotar Root CA",
		IssuerDN:          "diginotar root ca",
		Reason:            "compromised — *.google.com fraud (2011)",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2011-09-01",
	},
	{
		CommonName:        "DigiNotar Root CA G2",
		IssuerDN:          "diginotar root ca g2",
		Reason:            "DigiNotar G2 — distrusted alongside G1",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2011-09-01",
	},
	{
		CommonName:        "Camerfirma Chambers of Commerce Root - 2008",
		IssuerDN:          "chambers of commerce root - 2008",
		Reason:            "audit failures, mis-issuance (Camerfirma)",
		DistrustedBy:      []string{"Mozilla"},
		Since:             "2021-04-01",
	},
	{
		CommonName:        "Camerfirma Global Chambersign Root - 2008",
		IssuerDN:          "global chambersign root - 2008",
		Reason:            "Camerfirma global root — distrusted",
		DistrustedBy:      []string{"Mozilla"},
		Since:             "2021-04-01",
	},
	{
		CommonName:        "TrustCor RootCert CA-1",
		IssuerDN:          "trustcor rootcert ca-1",
		Reason:            "TrustCor distrust (2022) — surveillance-vendor ties",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2022-11-01",
	},
	{
		CommonName:        "TrustCor RootCert CA-2",
		IssuerDN:          "trustcor rootcert ca-2",
		Reason:            "TrustCor distrust (2022)",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2022-11-01",
	},
	{
		CommonName:        "TrustCor ECA-1",
		IssuerDN:          "trustcor eca-1",
		Reason:            "TrustCor ECA — distrusted with parent",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple", "Microsoft"},
		Since:             "2022-11-01",
	},
	{
		CommonName:        "e-Tugra Certification Authority",
		IssuerDN:          "e-tugra certification authority",
		Reason:            "October 2022 security incident — distrusted by browsers",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2023-04-01",
	},
	{
		CommonName:        "E-Tugra Global Root CA RSA v3",
		IssuerDN:          "e-tugra global root ca rsa v3",
		Reason:            "e-Tugra family — distrusted 2023",
		DistrustedBy:      []string{"Mozilla", "Chrome", "Apple"},
		Since:             "2023-04-01",
	},
	{
		CommonName:        "Entrust.net Certification Authority (Entrust)",
		IssuerDN:          "entrust root certification authority",
		Reason:            "Entrust distrust (2024) — operational failures",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "Entrust Root Certification Authority - G2",
		IssuerDN:          "entrust root certification authority - g2",
		Reason:            "Entrust G2 — distrusted 2024",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
	{
		CommonName:        "Entrust Root Certification Authority - EC1",
		IssuerDN:          "entrust root certification authority - ec1",
		Reason:            "Entrust EC1 — distrusted 2024",
		DistrustedBy:      []string{"Mozilla", "Chrome"},
		Since:             "2024-11-30",
	},
}

// distrustCheckResult records what we found, with confidence level per hit.
type distrustCheckResult struct {
	Hits []distrustHit `json:"hits,omitempty"`
}

// distrustHit pairs a chain cert with its distrust-DB entry + confidence.
type distrustHit struct {
	CertSubject string         `json:"cert_subject"`
	CertIssuer  string         `json:"cert_issuer"`
	Root        distrustedRoot `json:"root"`
	Confidence  string         `json:"confidence"` // "fingerprint" (HIGH) or "dn-match" (MEDIUM)
}

// checkChainDistrust walks every cert in a chain and matches each against
// the distrust DB by:
//   1. Subject Common Name canonical comparison (the cert IS the distrusted root)
//   2. Issuer Common Name comparison (the cert was ISSUED by a distrusted root)
//   3. Fingerprint match for higher-confidence flagging
func checkChainDistrust(chain []*x509.Certificate) distrustCheckResult {
	var out distrustCheckResult
	if len(chain) == 0 {
		return out
	}
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		// Hash for fingerprint comparison.
		sum := sha256.Sum256(cert.Raw)
		fp := strings.ToLower(hex.EncodeToString(sum[:]))

		// Build canonical comparison strings — lowercase the CommonName
		// fields of Subject and Issuer.
		subCN := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName))
		issCN := strings.ToLower(strings.TrimSpace(cert.Issuer.CommonName))

		for _, d := range distrustedRootDB {
			match := false
			confidence := ""

			// Highest confidence: exact fingerprint match.
			if d.FingerprintSHA256 != "" && fp == d.FingerprintSHA256 {
				match = true
				confidence = "fingerprint"
			}
			// Medium confidence: Subject CN matches the distrusted CA's
			// name. The cert IS the distrusted root (rarely seen mid-chain).
			if !match && subCN == d.IssuerDN {
				match = true
				confidence = "dn-match (cert is distrusted root)"
			}
			// Medium confidence: Issuer CN matches a distrusted CA.
			// The cert was ISSUED by a distrusted root.
			if !match && issCN == d.IssuerDN {
				match = true
				confidence = "dn-match (issued by distrusted root)"
			}
			if !match {
				continue
			}
			out.Hits = append(out.Hits, distrustHit{
				CertSubject: cert.Subject.CommonName,
				CertIssuer:  cert.Issuer.CommonName,
				Root:        d,
				Confidence:  confidence,
			})
		}
	}
	return out
}

// distrustHeadline returns the security-finding label for the hint line.
func distrustHeadline(r distrustCheckResult) string {
	if len(r.Hits) == 0 {
		return ""
	}
	if len(r.Hits) == 1 {
		return "DISTRUSTED root: " + r.Hits[0].Root.CommonName
	}
	return "DISTRUSTED roots ×" + itoa(len(r.Hits))
}
