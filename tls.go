package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// checkTLS performs a TLS handshake and inspects the certificate. It verifies
// manually (InsecureSkipVerify) so certificate details can be reported even
// when the certificate is invalid or expired.
func (d *diagnosis) checkTLS() Check {
	c := Check{Name: "TLS"}
	if d.scheme != "https" {
		c.Status = StatusSkip
		c.Summary = "skipped — not an HTTPS target"
		return c
	}
	if !d.resolved {
		c.Status = StatusSkip
		c.Summary = "skipped — DNS did not resolve"
		return c
	}

	addr := net.JoinHostPort(d.host, strconv.Itoa(d.port))
	dialer := &net.Dialer{Timeout: d.timeout}
	cfg := &tls.Config{
		ServerName:         d.host,
		InsecureSkipVerify: true,
	}

	start := time.Now()
	var conn *tls.Conn
	var err error
	if d.starttlsProto != "" {
		// STARTTLS path — connect plaintext, run the protocol-specific
		// upgrade dance, then wrap in tls.Client and handshake.
		conn, err = dialSTARTTLS(addr, d.host, d.starttlsProto, cfg, d.timeout)
	} else {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
	}
	handshake := time.Since(start)
	if err != nil {
		c.Status = StatusFail
		c.Summary = "TLS handshake failed"
		c.Detail = map[string]any{"error": tidyErr(err)}
		return c
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		c.Status = StatusFail
		c.Summary = "server presented no certificate"
		return c
	}

	leaf := st.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, ic := range st.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       d.host,
		Intermediates: intermediates,
	})

	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	version := tlsVersionName(st.Version)

	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	if issuer == "" {
		issuer = "unknown CA"
	}
	c.Hint = fmt.Sprintf("issued by %s  ·  expires %s",
		truncate(issuer, 32), leaf.NotAfter.Format("2 Jan 2006"))
	// Tack on key-algorithm + bits so the issuer line carries the most-asked
	// "what kind of cert is this" signal without crowding the headline.
	if kalg := keyAlgorithmName(leaf); kalg != "" {
		if kbits := keyBits(leaf); kbits > 0 {
			c.Hint += fmt.Sprintf("  ·  %s %d", kalg, kbits)
		} else {
			c.Hint += "  ·  " + kalg
		}
	}
	c.Millis = ms(handshake)

	// --- Augmented diagnostics: full chain, OCSP stapling, weak cipher, ---
	// --- version-support probe, HSTS (read from the trace).            ---
	type chainEntry struct {
		Subject           string   `json:"subject"`
		Issuer            string   `json:"issuer"`
		Expires           string   `json:"expires"`
		DNSNames          []string `json:"dns_names,omitempty"`
		KeyAlgorithm      string   `json:"key_algorithm,omitempty"` // RSA / ECDSA / Ed25519 / DSA
		KeyBits           int      `json:"key_bits,omitempty"`
		SignatureAlgo     string   `json:"signature_algorithm,omitempty"`
		SerialNumber      string   `json:"serial,omitempty"` // uppercase hex
		FingerprintSHA256 string   `json:"fingerprint_sha256,omitempty"`
		IsCA              bool     `json:"is_ca,omitempty"`
	}
	var chain []chainEntry
	for _, ic := range st.PeerCertificates {
		chain = append(chain, chainEntry{
			Subject:           ic.Subject.CommonName,
			Issuer:            ic.Issuer.CommonName,
			Expires:           ic.NotAfter.Format(time.RFC3339),
			DNSNames:          ic.DNSNames,
			KeyAlgorithm:      keyAlgorithmName(ic),
			KeyBits:           keyBits(ic),
			SignatureAlgo:     ic.SignatureAlgorithm.String(),
			SerialNumber:      strings.ToUpper(hex.EncodeToString(ic.SerialNumber.Bytes())),
			FingerprintSHA256: certFingerprintSHA256(ic),
			IsCA:              ic.IsCA,
		})
	}
	// OCSP stapling — parse the response if present so we can surface
	// Good/Revoked/Unknown + nextUpdate rather than just "is stapled".
	ocspStapled := len(st.OCSPResponse) > 0
	var ocspStatus, ocspNextUpdate string
	if ocspStapled {
		if resp, err := ocsp.ParseResponse(st.OCSPResponse, nil); err == nil {
			switch resp.Status {
			case ocsp.Good:
				ocspStatus = "Good"
			case ocsp.Revoked:
				ocspStatus = "Revoked"
			case ocsp.Unknown:
				ocspStatus = "Unknown"
			}
			if !resp.NextUpdate.IsZero() {
				ocspNextUpdate = resp.NextUpdate.Format(time.RFC3339)
			}
		}
	}
	// OCSP Must-Staple — TLS feature extension (OID 1.3.6.1.5.5.7.1.24)
	// signals the cert REQUIRES a stapled OCSP response. When set and the
	// server doesn't staple, that's a posture failure flag for the user.
	mustStaple := certHasMustStaple(leaf)
	// Wildcard cert detection — flag any wildcard in the SAN list so users
	// know they're under a *.domain.tld cert rather than an exact match.
	wildcardCert := false
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "*.") {
			wildcardCert = true
			break
		}
	}
	cipherWeak := isWeakCipher(st.CipherSuite)
	forwardSecret := isForwardSecret(st.CipherSuite)
	// SCTs come either via the TLS extension (rare in 2026) or embedded in the
	// leaf cert's X.509 extension (modern default for public CAs). Take
	// whichever source has data, then resolve log IDs to human-readable names
	// from our curated CT log database.
	sctCount := len(st.SignedCertificateTimestamps)
	var sctLogs []string
	if sctCount == 0 {
		sctCount = countEmbeddedSCTs(leaf)
		for _, ext := range leaf.Extensions {
			if oidEqual(ext.Id, sctExtensionOID) {
				sctLogs = listSCTLogs(ext.Value)
				break
			}
		}
	}

	// Posture probes run in parallel: TLS 1.0–1.3 version sweep, SSLv3
	// raw ClientHello (POODLE), SSLv2 raw probe (DROWN), session-
	// resumption double-Dial, Heartbleed raw probe, CRIME compression
	// probe, FREAK (RSA_EXPORT) probe, Logjam (DHE_EXPORT) probe,
	// CCS Injection crypto-grade probe, ALPN enumeration sweep,
	// extension-posture probe (EMS + RFC 5746), DH parameter parse
	// (Logjam common-prime check).
	// FALLBACK_SCSV runs after — it needs the version sweep's max result.
	var versionProbes []tlsVersionProbe
	var sslv3Supported, sslv2Supported bool
	var sessionResumed, heartbleed, crime, freak, logjam, ccsInjection bool
	var ticketbleed bool
	var scsvProtected, scsvConclusive bool
	var alpnList []string
	var extPosture tlsExtensionPosture
	var dhPosture dhParameterPosture
	var ech echPosture
	var jarm jarmResult
	var wg sync.WaitGroup
	wg.Add(15)
	go func() { defer wg.Done(); versionProbes = probeTLSVersions(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); sslv3Supported = probeSSLv3(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); sslv2Supported = probeSSLv2(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); sessionResumed = probeSessionResumption(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); heartbleed = probeHeartbleed(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); crime = probeCRIME(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); freak = probeFREAK(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); logjam = probeLogjam(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); ccsInjection = probeCCSInjection(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); alpnList = probeALPN(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); extPosture = probeTLSExtensions(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); dhPosture = probeDHParameters(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); ech = probeECH(d.host, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); ticketbleed = probeTicketbleed(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); jarm = probeJARM(d.host, d.port, d.timeout) }()
	var pqc pqcResult
	var cbcOracles cbcOracleResult
	var robot robotResult
	var zeroRTT zeroRTTResult
	var reneg renegResult
	wg.Add(5)
	go func() { defer wg.Done(); pqc = probePQC(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); cbcOracles = probeCBCOracles(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); robot = probeROBOT(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); zeroRTT = probeZeroRTTPrereqs(d.host, d.port, d.timeout) }()
	go func() { defer wg.Done(); reneg = probeClientInitReneg(d.host, d.port, d.timeout) }()
	wg.Wait()
	// FALLBACK_SCSV needs to know the server's max supported version, so it
	// runs after the version probe rather than in parallel with it.
	maxVer := maxSupportedVersion(versionProbes)
	if maxVer != 0 {
		scsvProtected, scsvConclusive = probeFallbackSCSV(d.host, d.port, maxVer, d.timeout)
	}

	// DANE / TLSA — look up _<port>._tcp.<host> and check whether any
	// TLSA record matches the cert chain we saw. Meaningful only when
	// the answer is itself DNSSEC-validated; we surface the verdict here
	// and let the user cross-reference DNSSEC: chain-validated in DNS.
	daneRes := probeDANE(d.host, d.port, leaf, st.PeerCertificates, d.dnsTransport, d.timeout)

	// Cipher-suite enumeration per supported TLS version — the SSL Labs
	// flagship table. We probe ~30 IANA cipher suites at 1.2 and 5 at 1.3,
	// each via a one-cipher ClientHello, observing whether the server
	// accepts. Skipped per-version when that version isn't supported.
	// Once enumerated, we also run a cipher-preference-order probe per
	// version (two ordered ClientHellos with the supported set in opposite
	// orders) — the SSL Labs "server preference" column.
	var cipherEnums []cipherEnum
	var cipherPreferences []cipherPreferenceResult
	for _, p := range versionProbes {
		if !p.Supported {
			continue
		}
		var pinned uint16
		var candidates []uint16
		switch p.Name {
		case "TLS 1.3":
			pinned = tls.VersionTLS13
			candidates = candidateCiphersTLS13
		case "TLS 1.2":
			pinned = tls.VersionTLS12
			candidates = candidateCiphersTLS12
		case "TLS 1.1":
			pinned = tls.VersionTLS11
			candidates = candidateCiphersTLS12
		case "TLS 1.0":
			pinned = tls.VersionTLS10
			candidates = candidateCiphersTLS12
		default:
			continue
		}
		got := enumerateCiphers(d.host, d.port, pinned, candidates, d.timeout)
		if len(got) == 0 {
			continue
		}
		worst := "A"
		for _, ci := range got {
			if grade2rank(ci.Grade) < grade2rank(worst) {
				worst = ci.Grade
			}
		}
		cipherEnums = append(cipherEnums, cipherEnum{
			TLSVersion: p.Name,
			Ciphers:    got,
			WorstGrade: worst,
		})
		if len(got) >= 2 {
			codes := make([]uint16, 0, len(got))
			for _, ci := range got {
				codes = append(codes, ci.Code)
			}
			pref := probeCipherPreference(d.host, d.port, pinned, codes, d.timeout)
			if pref.Order != "" {
				cipherPreferences = append(cipherPreferences, pref)
			}
		}
	}

	supportedVersions := supportedVersionNames(versionProbes)
	tls10Cipher := tls10CipherIfSupported(versionProbes)

	weakVersions := false
	for _, v := range supportedVersions {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			weakVersions = true
			break
		}
	}

	vulns := detectTLSVulns(st.CipherSuite, tls10Cipher, sslv3Supported, sslv2Supported, heartbleed, crime, freak, logjam, ccsInjection, dhPosture, extPosture)
	if ticketbleed {
		vulns = append(vulns, tlsVuln{
			Name:        "Ticketbleed",
			CVE:         "CVE-2016-9244",
			Description: "F5 BIG-IP echoed server memory in session_id (Ticketbleed)",
			Severity:    "high",
		})
	}
	if cbcOracles.GoldenDoodle {
		vulns = append(vulns, tlsVuln{
			Name:        "GOLDENDOODLE",
			CVE:         "CVE-2019-1559",
			Description: "CBC padding oracle — distinguishable alert codes",
			Severity:    "high",
		})
	}
	if cbcOracles.ZombiePoodle {
		vulns = append(vulns, tlsVuln{
			Name:        "Zombie POODLE",
			CVE:         "CVE-2019-6593",
			Description: "CBC padding oracle — observable response-length differences",
			Severity:    "high",
		})
	}
	if cbcOracles.SleepingPoodle {
		vulns = append(vulns, tlsVuln{
			Name:        "Sleeping POODLE",
			CVE:         "CVE-2019-6593",
			Description: "CBC padding oracle — observable response-timing differences",
			Severity:    "medium",
		})
	}
	if robot.Vulnerable {
		vulns = append(vulns, tlsVuln{
			Name:        "ROBOT",
			CVE:         "CVE-2017-13099",
			Description: "Bleichenbacher oracle — distinguishable RSA decryption responses",
			Severity:    "high",
		})
	}
	if reneg.DoSAmplification {
		vulns = append(vulns, tlsVuln{
			Name:        "Client-init renegotiation DoS",
			CVE:         "CVE-2011-1473",
			Description: "server accepts unrate-limited client-initiated TLS renegotiation — DoS amplification vector",
			Severity:    "medium",
		})
	} else if reneg.ClientInitAccepted {
		vulns = append(vulns, tlsVuln{
			Name:        "Client-init renegotiation",
			CVE:         "",
			Description: "server accepts client-initiated renegotiation — should be disabled or rate-limited",
			Severity:    "low",
		})
	}
	// Distrusted-CA chain check.
	distrust := checkChainDistrust(st.PeerCertificates)
	for _, hit := range distrust.Hits {
		vulns = append(vulns, tlsVuln{
			Name:        "Distrusted CA: " + hit.Root.CommonName,
			CVE:         "",
			Description: hit.Root.Reason + " (distrusted by " + strings.Join(hit.Root.DistrustedBy, ", ") + " since " + hit.Root.Since + ")",
			Severity:    "high",
		})
	}

	c.Detail = map[string]any{
		"version":            version,
		"cipher":             tls.CipherSuiteName(st.CipherSuite),
		"cipher_weak":        cipherWeak,
		"forward_secrecy":    forwardSecret,
		"alpn":               st.NegotiatedProtocol,
		"handshake_ms":       ms(handshake),
		"issuer":             leaf.Issuer.CommonName,
		"subject":            leaf.Subject.CommonName,
		"expires":            leaf.NotAfter.Format(time.RFC3339),
		"days_left":          daysLeft,
		"chain":              chain,
		"key_algorithm":      keyAlgorithmName(leaf),
		"key_bits":           keyBits(leaf),
		"signature_algo":     leaf.SignatureAlgorithm.String(),
		"san_count":          len(leaf.DNSNames),
		"wildcard_cert":      wildcardCert,
		"fingerprint_sha256": certFingerprintSHA256(leaf),
		"ocsp_stapled":       ocspStapled,
		"must_staple":        mustStaple,
		"sct_count":          sctCount,
		"session_resumption": sessionResumed,
		"supported_versions": supportedVersions,
		"weak_versions":      weakVersions,
		"sslv3":              sslv3Supported,
	}
	if ocspStatus != "" {
		c.Detail["ocsp_status"] = ocspStatus
	}
	if ocspNextUpdate != "" {
		c.Detail["ocsp_next_update"] = ocspNextUpdate
	}
	// CRL revocation check — complements OCSP. Surfaces leaf-revocation
	// status, CRL freshness, and revocation count regardless of which
	// revocation mechanism the CA emphasizes (some CAs are pivoting away
	// from OCSP post-2025 Mozilla policy changes).
	if len(st.PeerCertificates) > 0 {
		crl := probeCRL(st.PeerCertificates[0], d.timeout)
		if crl.Attempted {
			c.Detail["crl"] = crl
		}
	}
	if scsvConclusive {
		c.Detail["fallback_scsv"] = scsvProtected
	}
	if daneRes != nil {
		c.Detail["dane"] = daneRes
	}
	if len(cipherEnums) > 0 {
		c.Detail["cipher_enum"] = cipherEnums
	}
	// --each-cipher: full IANA-registry enumeration via the elimination
	// algorithm. Slower than the routine cipher_enum (which only probes
	// modern ciphers per TLS version) but reveals every legacy/obscure
	// cipher the server still accepts. Closes the testssl --each-cipher gap.
	if d.eachCipher {
		each := eachCipherAllVersions(d.host, d.port, d.timeout)
		if len(each) > 0 {
			c.Detail["each_cipher"] = each
			c.Detail["each_cipher_summary"] = summarizeEachCipher(each)
		}
	}
	if len(cipherPreferences) > 0 {
		c.Detail["cipher_preference"] = cipherPreferences
	}
	if len(alpnList) > 0 {
		c.Detail["alpn_offered"] = alpnList
	}
	if extPosture.Determined {
		c.Detail["extended_master_secret"] = extPosture.ExtendedMasterSecret
		c.Detail["secure_renegotiation"] = extPosture.SecureRenegotiation
	}
	if dhPosture.Determined && dhPosture.Supported {
		c.Detail["dh_parameters"] = dhPosture
	}
	if ech.Supported {
		c.Detail["ech"] = ech
	}
	if jarm.Fingerprint != "" && strings.Trim(jarm.Fingerprint, "0") != "" {
		c.Detail["jarm"] = jarm
	}
	// JA4S server fingerprint — Foxio's 2023 successor to JA3/JARM.
	// Computed from the FIRST JARM probe's ServerHello body (which we
	// don't directly retain — instead we send a dedicated ClientHello).
	ja4 := computeJA4SFromHandshake(d.host, d.port, d.timeout)
	if ja4.JA4S != "" {
		c.Detail["ja4s"] = ja4
	}
	// JA3S — server fingerprint from the main handshake's ServerHello.
	// We don't have the raw ServerHello body here (crypto/tls hides it),
	// but we can synthesize an equivalent triple from ConnectionState +
	// negotiated extensions. Skip when we lack signal.
	var ja3sFingerprint string
	if st.Version != 0 && st.CipherSuite != 0 {
		// Build a minimal "raw" since crypto/tls doesn't expose the full
		// extension list. We approximate using version+cipher+ALPN+OCSP.
		var ja3sExt []string
		if st.NegotiatedProtocol != "" {
			ja3sExt = append(ja3sExt, "16") // ALPN extension type
		}
		if len(st.OCSPResponse) > 0 {
			ja3sExt = append(ja3sExt, "5") // status_request
		}
		if len(st.SignedCertificateTimestamps) > 0 {
			ja3sExt = append(ja3sExt, "18") // signed_certificate_timestamp
		}
		raw := decimalUint16(st.Version) + "," + decimalUint16(st.CipherSuite) + "," + strings.Join(ja3sExt, "-")
		sum := md5sum([]byte(raw))
		ja3sFingerprint = sum
		c.Detail["ja3s"] = map[string]any{
			"hash":      sum,
			"raw":       raw,
			"version":   st.Version,
			"cipher":    st.CipherSuite,
			"ext_count": len(ja3sExt),
		}
	}
	// Mozilla TLS profile compliance — modern / intermediate / old.
	mozilla := evaluateMozillaCompliance(versionProbes, cipherEnums)
	c.Detail["mozilla_profile"] = mozilla
	if d.trace != nil && d.trace.HSTS != "" {
		c.Detail["hsts"] = d.trace.HSTS
	}
	if len(vulns) > 0 {
		c.Detail["vulnerabilities"] = vulns
	}

	// Build the second hint line summarising the security posture. SSL 3.0
	// is prepended to the version list when supported so the user sees the
	// full set the server speaks.
	var second []string
	versionList := supportedVersions
	if sslv3Supported {
		versionList = append([]string{"SSL 3.0"}, supportedVersions...)
	}
	if len(versionList) > 0 {
		second = append(second, strings.Join(versionList, "/"))
	}
	switch {
	case ocspStapled && ocspStatus != "":
		second = append(second, "OCSP "+ocspStatus)
	case ocspStapled:
		second = append(second, "OCSP stapled")
	case mustStaple:
		// Cert demands stapling but server didn't deliver — a posture failure.
		second = append(second, "Must-Staple set but no staple")
	}
	if mustStaple && ocspStapled {
		second = append(second, "Must-Staple")
	}
	if wildcardCert {
		second = append(second, "wildcard cert")
	}
	if d.trace != nil && d.trace.HSTS != "" {
		second = append(second, "HSTS")
	}
	if sctCount > 0 {
		label := fmt.Sprintf("SCT×%d", sctCount)
		if len(sctLogs) > 0 {
			// Show up to 2 log names inline; more would crowd the line.
			shown := sctLogs
			if len(shown) > 2 {
				shown = shown[:2]
			}
			label += " (" + strings.Join(shown, ", ") + ")"
		}
		second = append(second, label)
	}
	if st.NegotiatedProtocol == "h2" {
		second = append(second, "HTTP/2 ALPN")
	} else if st.NegotiatedProtocol != "" && st.NegotiatedProtocol != "http/1.1" {
		second = append(second, "ALPN: "+st.NegotiatedProtocol)
	}
	if daneRes != nil {
		if daneRes.AnyMatched {
			second = append(second, fmt.Sprintf("DANE×%d ✓", len(daneRes.Records)))
		} else {
			second = append(second, fmt.Sprintf("DANE×%d unmatched", len(daneRes.Records)))
		}
	}
	if len(cipherEnums) > 0 {
		var parts []string
		for _, ce := range cipherEnums {
			parts = append(parts, fmt.Sprintf("%s×%d %s", ce.TLSVersion, len(ce.Ciphers), ce.WorstGrade))
		}
		second = append(second, "ciphers: "+strings.Join(parts, ", "))
	}
	// --each-cipher headline. Surfaces the breakdown of accepted
	// codepoints by severity. Full list is in JSON detail.each_cipher.
	if v, ok := c.Detail["each_cipher_summary"]; ok {
		if s, ok := v.(eachCipherSummary); ok && s.Total > 0 {
			var ecParts []string
			if s.Broken > 0 {
				ecParts = append(ecParts, fmt.Sprintf("%d broken", s.Broken))
			}
			if s.Weak > 0 {
				ecParts = append(ecParts, fmt.Sprintf("%d weak", s.Weak))
			}
			if s.Policy > 0 {
				ecParts = append(ecParts, fmt.Sprintf("%d policy", s.Policy))
			}
			if s.Modern > 0 {
				ecParts = append(ecParts, fmt.Sprintf("%d modern", s.Modern))
			}
			second = append(second, fmt.Sprintf("each-cipher: %d total (%s)", s.Total, strings.Join(ecParts, ", ")))
		}
	}
	// Cipher preference order. SSL-Labs flagship column: did the server pick
	// its own preferred cipher (recommended) or follow our offer order?
	if len(cipherPreferences) > 0 {
		// If every supported version has the same verdict, summarise once.
		// Otherwise list each.
		allSame := true
		first := cipherPreferences[0].Order
		for _, p := range cipherPreferences[1:] {
			if p.Order != first {
				allSame = false
				break
			}
		}
		if allSame {
			second = append(second, "cipher pref: "+first)
		} else {
			var parts []string
			for _, p := range cipherPreferences {
				parts = append(parts, p.TLSVersion+":"+p.Order)
			}
			second = append(second, "cipher pref: "+strings.Join(parts, ", "))
		}
	}
	// ALPN advertised list — show all protocols the server accepts, not just
	// what got picked in the headline handshake. Suppress when only one
	// protocol is accepted AND it matches the negotiated one (already shown).
	if len(alpnList) > 0 {
		showList := alpnList
		if len(showList) == 1 && showList[0] == st.NegotiatedProtocol {
			// Already in the headline ALPN entry — skip the duplicate.
		} else {
			second = append(second, "ALPN supported: "+strings.Join(showList, ", "))
		}
	}
	// Extended Master Secret — RFC 7627. Modern servers MUST advertise it.
	// Absence is a posture warning, not a CVE per se.
	if extPosture.Determined && !extPosture.ExtendedMasterSecret {
		second = append(second, "no EMS")
	}
	// DH parameters — surface bit-length and any common-prime hit. Insecure
	// values are also turned into vulnerabilities[] entries above; the line
	// here is the informational summary for healthy servers.
	if dhPosture.Determined && dhPosture.Supported {
		label := fmt.Sprintf("DH %d-bit", dhPosture.Bits)
		if dhPosture.PrimeName != "" {
			label += " (" + dhPosture.PrimeName + ")"
		}
		second = append(second, label)
	}
	if v := echHeadline(ech); v != "" {
		second = append(second, v)
	}
	if v := jarmHeadline(jarm); v != "" {
		second = append(second, v)
	}
	if v := ja4Headline(ja4); v != "" {
		second = append(second, v)
	}
	if v := mozillaHeadline(mozilla); v != "" {
		second = append(second, v)
	}
	if v := pqcHeadline(pqc); v != "" {
		second = append(second, v)
	}
	if v := cbcOracleHeadline(cbcOracles); v != "" {
		second = append(second, v)
	}
	if v := distrustHeadline(distrust); v != "" {
		second = append(second, v)
	}
	// HSTS preload list membership check — apex domain lookup.
	hstsPreload := checkHSTSPreloaded(d.host)
	if v := hstsPreloadHeadline(hstsPreload); v != "" {
		second = append(second, v)
	}
	if hstsPreload.InEmbeddedSet {
		c.Detail["hsts_preload"] = hstsPreload
	}
	if v := robotHeadline(robot); v != "" {
		second = append(second, v)
	}
	if v := zeroRTTHeadline(zeroRTT); v != "" {
		second = append(second, v)
	}
	if pqc.Probed {
		c.Detail["pqc"] = pqc
	}
	if cbcOracles.Probed {
		c.Detail["cbc_oracles"] = cbcOracles
	}
	if len(distrust.Hits) > 0 {
		c.Detail["distrusted_roots"] = distrust.Hits
	}
	if robot.Probed {
		c.Detail["robot"] = robot
	}
	if zeroRTT.Probed {
		c.Detail["zero_rtt"] = zeroRTT
	}
	if reneg.Probed {
		c.Detail["client_init_reneg"] = reneg
	}
	// Client simulation matrix — closes the testssl.sh `-c` flag gap.
	// Runs ~26 named client profiles against the target and reports
	// which would successfully handshake. Cost: ~28 parallel handshakes
	// with concurrency 8, typically <2s wall clock.
	sims := simulateClients(d.host, d.port, d.host, d.starttlsProto, d.timeout)
	c.Detail["client_simulation"] = sims
	if h := simulateClientsHeadline(sims); h != "" {
		second = append(second, h)
	}

	// --cipher-pattern <p> — testssl -x equivalent. When set, surface a
	// curated subset of matching ciphers separately from the full enum.
	if d.cipherPattern != "" {
		match := filterCiphersByPattern(cipherEnums, d.cipherPattern)
		c.Detail["cipher_pattern_match"] = match
		if match.HitCount > 0 {
			second = append(second, fmt.Sprintf("pattern %q: %d cipher match%s offered",
				d.cipherPattern, match.HitCount, esIfPlural(match.HitCount)))
		} else {
			second = append(second, fmt.Sprintf("pattern %q: no matches in offered ciphers ✓", d.cipherPattern))
		}
	}

	// BREACH (CVE-2013-3587) — HTTP compression detection. Skip for
	// STARTTLS targets (not an HTTP service).
	if d.starttlsProto == "" {
		breach := probeBREACH(d.host, d.port, d.timeout)
		if breach.Probed {
			c.Detail["breach"] = breach
			if h := breachHeadline(breach); h != "" {
				second = append(second, h)
			}
		}
	}

	// Winshock CVE-2014-6321 — passive Schannel inference from JARM /
	// JA3S / HTTP Server header. Surfaces risk surface without invasive
	// probing.
	serverHdr := ""
	if d.trace != nil && d.trace.Headers != nil {
		serverHdr = d.trace.Headers.Get("Server")
	}
	winshock := probeWinshock(jarm.Fingerprint, ja3sFingerprint, ja4.JA4S, serverHdr)
	if winshock.Probed {
		c.Detail["winshock"] = winshock
		if h := winshockHeadline(winshock); h != "" {
			second = append(second, h)
		}
	}

	// Obscure cipher probe — hand-rolled TLS 1.2 ClientHello listing
	// only GOST / Camellia / SEED / ARIA / IDEA / RC2 / NULL ciphers.
	// Server's ServerHello selection (or refusal alert) tells us
	// whether ANY of those classes is offered. Skip for STARTTLS since
	// the upgrade path would need protocol-specific handshake first;
	// the main cipher_enum covers STARTTLS via Go's stdlib.
	if d.starttlsProto == "" {
		obscure := probeObscureCiphers(d.host, d.port, d.timeout)
		if obscure.Probed {
			c.Detail["obscure_ciphers"] = obscure
			if h := obscureCipherHeadline(obscure); h != "" {
				second = append(second, h)
			}
		}
	}

	// STARTTLS Injection (CVE-2011-0411 family) — pipelined-command
	// probe. Only fires when --starttls is set and the protocol is one
	// we have an injection plan for (smtp/imap/pop3/ftp/nntp).
	if d.starttlsProto != "" {
		inj := probeSTARTTLSInjection(net.JoinHostPort(d.host, strconv.Itoa(d.port)), d.host, d.starttlsProto, d.timeout)
		if inj.Probed {
			c.Detail["starttls_injection"] = inj
			if h := starttlsInjectionHeadline(inj); h != "" {
				second = append(second, h)
			}
		}
	}

	// SSL Labs-class A+/A/B/C/D/F grade. Aggregates everything we
	// already collected into a single defensible letter, with the
	// reasoning surfaced in JSON detail for transparency.
	hstsValid := false
	hstsPreloaded := false
	if d.trace != nil && d.trace.Headers != nil {
		hsts := d.trace.Headers.Get("Strict-Transport-Security")
		hstsValid = strings.Contains(strings.ToLower(hsts), "max-age=") &&
			!strings.Contains(strings.ToLower(hsts), "max-age=0")
		hstsPreloaded = strings.Contains(strings.ToLower(hsts), "preload")
	}
	// Flatten cipher_enum into a single list for grading.
	var allCiphers []cipherInfo
	for _, ce := range cipherEnums {
		allCiphers = append(allCiphers, ce.Ciphers...)
	}
	grade := gradeTLS(
		supportedVersions,
		allCiphers,
		leaf,
		hstsValid,
		hstsPreloaded,
		ocspStapled,
		mustStaple,
		forwardSecret,
		dhPosture.Determined && dhPosture.Supported && dhPosture.Bits > 0 && dhPosture.Bits < 2048,
		heartbleed,
		robot.Vulnerable,
		reneg.ClientInitAccepted, // proxy for insecure renegotiation (RFC 5746 absent)
	)
	c.Detail["grade"] = grade
	second = append(second, gradeHeadline(grade))
	if sessionResumed {
		second = append(second, "resumption")
	}
	// Suppress generic "weak cipher" when SWEET32 already names the issue.
	if cipherWeak && !is3DESCipher(st.CipherSuite) {
		second = append(second, "weak cipher")
	}
	if !forwardSecret {
		second = append(second, "no forward secrecy")
	}
	if scsvConclusive && !scsvProtected {
		second = append(second, "no FALLBACK_SCSV")
	}
	if weakVersions {
		second = append(second, "allows TLS 1.0/1.1")
	}
	for _, v := range vulns {
		second = append(second, v.Name)
	}
	if len(second) > 0 {
		c.Hint += "\n" + strings.Join(second, "  ·  ")
	}

	worst := worstVulnerability(vulns)

	switch {
	case verifyErr != nil:
		c.Status = StatusFail
		c.Summary = "certificate problem — " + tidyErr(verifyErr)
	case daysLeft < 0:
		c.Status = StatusFail
		c.Summary = "certificate has expired"
	case daysLeft < 21:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%s — certificate expires in %d day%s", version, daysLeft, plural(daysLeft))
	case worst != nil && worst.severityRank() >= 3:
		c.Status = StatusFail
		c.Summary = vulnSummary(vulns)
	case worst != nil:
		c.Status = StatusWarn
		c.Summary = vulnSummary(vulns)
	case cipherWeak:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%s — weak cipher negotiated (%s)", version, tls.CipherSuiteName(st.CipherSuite))
	case weakVersions:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%s — server allows deprecated TLS 1.0/1.1", version)
	default:
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("%s — certificate valid for %d more day%s", version, daysLeft, plural(daysLeft))
	}
	return c
}

// vulnSummary formats the headline for the TLS check when one or more known
// vulnerabilities are detected. Single-vuln output names the CVE; multi-vuln
// output lists the names so the user knows the full set at a glance.
func vulnSummary(vulns []tlsVuln) string {
	if len(vulns) == 1 {
		v := vulns[0]
		return fmt.Sprintf("%s (%s) — %s", v.Name, v.CVE, v.Description)
	}
	names := make([]string, len(vulns))
	for i, v := range vulns {
		names[i] = v.Name
	}
	return "vulnerable: " + strings.Join(names, ", ")
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS (0x%04x)", v)
	}
}

// isWeakCipher returns true for cipher suites considered deprecated or weak by
// modern standards — RC4, 3DES, and CBC-mode RSA suites without AEAD.
func isWeakCipher(suite uint16) bool {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return true
	}
	return false
}

// tlsVersionProbe records what one pinned-version handshake found: whether
// the server accepted that version, and if so, which cipher suite it picked.
// The cipher is what makes BEAST detection accurate — we need to know what
// the server would negotiate *under TLS 1.0*, not under our normal session.
type tlsVersionProbe struct {
	Name      string
	Supported bool
	Cipher    uint16
}

// probeTLSVersions opens four concurrent TLS connections, one per version
// pinned via MinVersion=MaxVersion, and returns one tlsVersionProbe per
// version. Used to surface "server still allows TLS 1.0/1.1" and to provide
// the per-version cipher info that drives BEAST detection.
func probeTLSVersions(host string, port int, timeout time.Duration) []tlsVersionProbe {
	versions := []tlsVersionProbe{
		{Name: "TLS 1.0"},
		{Name: "TLS 1.1"},
		{Name: "TLS 1.2"},
		{Name: "TLS 1.3"},
	}
	verIDs := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

	perProbe := timeout
	if perProbe > 800*time.Millisecond {
		perProbe = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	type res struct {
		idx    int
		ok     bool
		cipher uint16
	}
	out := make(chan res, len(versions))
	for i, ver := range verIDs {
		go func(idx int, ver uint16) {
			dialer := &net.Dialer{Timeout: perProbe}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				MinVersion:         ver,
				MaxVersion:         ver,
			})
			r := res{idx: idx}
			if err == nil {
				r.ok = true
				r.cipher = conn.ConnectionState().CipherSuite
				conn.Close()
			}
			out <- r
		}(i, ver)
	}
	for i := 0; i < len(versions); i++ {
		r := <-out
		versions[r.idx].Supported = r.ok
		versions[r.idx].Cipher = r.cipher
	}
	return versions
}

// supportedVersionNames extracts the human-readable names of TLS versions the
// server accepted, in protocol order.
func supportedVersionNames(probes []tlsVersionProbe) []string {
	var out []string
	for _, p := range probes {
		if p.Supported {
			out = append(out, p.Name)
		}
	}
	return out
}

// tls10CipherIfSupported returns the cipher the server negotiated under a
// pinned TLS 1.0 handshake, or 0 if TLS 1.0 was not supported.
func tls10CipherIfSupported(probes []tlsVersionProbe) uint16 {
	for _, p := range probes {
		if p.Name == "TLS 1.0" && p.Supported {
			return p.Cipher
		}
	}
	return 0
}

// grade2rank converts a letter grade (A best, F worst) into a sortable rank.
// Used by the cipher-enum worst-grade aggregation.
func grade2rank(g string) int {
	switch g {
	case "A":
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

// keyAlgorithmName renders an x509 public-key algorithm as a short string —
// "RSA", "ECDSA", "Ed25519", "Ed448", "DSA", or "" for unknown.
func keyAlgorithmName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	}
	return ""
}

// keyBits returns the modulus / curve / key size in bits, or 0 when the key
// is an algorithm we don't introspect.
func keyBits(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// certFingerprintSHA256 returns the colon-separated uppercase hex SHA-256
// fingerprint of a cert's DER bytes — the standard format browsers + most
// CLI tools use.
func certFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	// Insert ":" every two hex chars for readability.
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// mustStapleOID is the X.509 TLS Feature extension OID (RFC 7633). When a
// cert carries this extension with value containing the status_request
// feature (id 5), the cert REQUIRES a stapled OCSP response.
var mustStapleOID = []int{1, 3, 6, 1, 5, 5, 7, 1, 24}

// certHasMustStaple checks whether the cert carries the TLS Feature extension
// listing status_request (= 5). The extension value is a DER SEQUENCE OF
// INTEGER; we scan it for byte 0x05 between the SEQUENCE tag and the end.
func certHasMustStaple(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if !oidEqual(ext.Id, mustStapleOID) {
			continue
		}
		// Extension value is DER SEQUENCE OF INTEGER. Scan for integer 5.
		// Format: 0x30 LEN [0x02 0x01 VAL] [0x02 0x01 VAL] ...
		v := ext.Value
		if len(v) < 2 || v[0] != 0x30 {
			return false
		}
		i := 2
		for i+2 < len(v) {
			if v[i] == 0x02 && v[i+1] == 0x01 && v[i+2] == 0x05 {
				return true
			}
			i += 3
		}
	}
	return false
}

// maxSupportedVersion returns the highest TLS protocol version the server
// accepted across the pinned-version probes, encoded as a wire-format version
// number (0x0303 = TLS 1.2, etc.). Returns 0 if no version was accepted.
func maxSupportedVersion(probes []tlsVersionProbe) uint16 {
	versionOf := map[string]uint16{
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"TLS 1.2": tls.VersionTLS12,
		"TLS 1.3": tls.VersionTLS13,
	}
	var max uint16
	for _, p := range probes {
		if !p.Supported {
			continue
		}
		v := versionOf[p.Name]
		if v > max {
			max = v
		}
	}
	return max
}
