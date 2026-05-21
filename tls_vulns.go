package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// tlsVuln describes one known TLS vulnerability detected on the server.
// The set is intentionally a small, high-signal subset of testssl.sh's
// catalogue — only items reliably detectable from Go's stdlib TLS plus
// a small amount of hand-rolled wire-format probing.
type tlsVuln struct {
	Name        string `json:"name"`
	CVE         string `json:"cve"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "critical" | "high" | "medium" | "low"
}

// severityRank returns a sortable rank for picking which vuln headlines the
// summary when multiple are detected. Higher = worse.
func (v tlsVuln) severityRank() int {
	switch v.Severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// isCBCCipher reports whether the suite uses CBC mode. CBC suites under
// TLS 1.0 are vulnerable to BEAST (CVE-2011-3389).
func isCBCCipher(suite uint16) bool {
	switch suite {
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return true
	}
	return false
}

// is3DESCipher reports whether the suite uses 3DES — vulnerable to SWEET32
// (CVE-2016-2183) birthday attacks against the 64-bit block size.
func is3DESCipher(suite uint16) bool {
	return suite == tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

// isRC4Cipher reports whether the suite uses RC4 — vulnerable to RC4
// biases (CVE-2013-2566 / CVE-2015-2808). RFC 7465 prohibits RC4 entirely.
func isRC4Cipher(suite uint16) bool {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return true
	}
	return false
}

// detectTLSVulns surfaces known TLS vulnerabilities given the handshake state
// plus the auxiliary probes. `cipher` is what the server negotiated in the
// main session; `tls10Cipher` is what the server negotiated when pinned to
// TLS 1.0 (0 means TLS 1.0 was refused). The TLS 1.0 cipher is what really
// drives BEAST — checking only the main-session cipher misses servers that
// support TLS 1.0+CBC but normally negotiate TLS 1.3+AEAD.
//
// dhPosture carries the DH parameter analysis (Logjam common-prime + bit
// length); extPosture carries Extended Master Secret + RFC 5746 secure
// renegotiation negotiation status. Both extend Logjam coverage beyond the
// DHE_EXPORT-only `logjam` flag.
func detectTLSVulns(cipher, tls10Cipher uint16, sslv3, sslv2, heartbleed, crime, freak, logjam, ccsInjection bool, dhPosture dhParameterPosture, extPosture tlsExtensionPosture) []tlsVuln {
	var vulns []tlsVuln

	// Heartbleed — sent up front because it's the headline (CVE-2014-0160).
	if heartbleed {
		vulns = append(vulns, tlsVuln{
			Name:        "Heartbleed",
			CVE:         "CVE-2014-0160",
			Description: "OpenSSL Heartbeat leaks server memory — UPDATE NOW",
			Severity:    "critical",
		})
	}

	// DROWN — SSLv2 must be off entirely; any SSLv2 acceptance is a DROWN
	// vector (CVE-2016-0800) on the affected server AND on any other server
	// that shares its RSA key.
	if sslv2 {
		vulns = append(vulns, tlsVuln{
			Name:        "DROWN",
			CVE:         "CVE-2016-0800",
			Description: "SSLv2 enabled — cross-protocol private-key recovery",
			Severity:    "critical",
		})
	}

	// CRIME — server agreed to TLS compression (CVE-2012-4929). Enables
	// chosen-plaintext recovery of session cookies / auth headers.
	if crime {
		vulns = append(vulns, tlsVuln{
			Name:        "CRIME",
			CVE:         "CVE-2012-4929",
			Description: "TLS compression enabled — chosen-plaintext cookie recovery",
			Severity:    "high",
		})
	}

	// FREAK — server accepts RSA_EXPORT ciphers (CVE-2015-0204).
	if freak {
		vulns = append(vulns, tlsVuln{
			Name:        "FREAK",
			CVE:         "CVE-2015-0204",
			Description: "RSA_EXPORT cipher accepted — factorable-RSA downgrade",
			Severity:    "high",
		})
	}

	// Logjam — server accepts DHE_EXPORT ciphers (CVE-2015-4000).
	if logjam {
		vulns = append(vulns, tlsVuln{
			Name:        "Logjam",
			CVE:         "CVE-2015-4000",
			Description: "DHE_EXPORT cipher accepted — 512-bit DH downgrade",
			Severity:    "high",
		})
	}

	// Logjam common-prime — server's DH parameters use a widely-shared 1024-bit
	// (or smaller) prime that's precomputable for a nation-state attacker per
	// the Logjam paper. Distinct from the DHE_EXPORT probe above: this catches
	// servers using strong-by-default cipher suites but weak-prime DH groups.
	if dhPosture.Determined && dhPosture.Supported {
		switch {
		case dhPosture.Bits > 0 && dhPosture.Bits < 1024:
			vulns = append(vulns, tlsVuln{
				Name:        "Weak DH",
				CVE:         "CVE-2015-4000",
				Description: fmt.Sprintf("DH prime is %d bits — well below 2048-bit recommendation", dhPosture.Bits),
				Severity:    "high",
			})
		case dhPosture.CommonPrime && dhPosture.Bits <= 1024:
			vulns = append(vulns, tlsVuln{
				Name:        "Logjam common-prime",
				CVE:         "CVE-2015-4000",
				Description: fmt.Sprintf("DH uses 1024-bit shared prime — %s", dhPosture.PrimeName),
				Severity:    "high",
			})
		case dhPosture.Bits == 1024 && !dhPosture.CommonPrime:
			vulns = append(vulns, tlsVuln{
				Name:        "Weak DH",
				CVE:         "CVE-2015-4000",
				Description: "DH prime is 1024 bits — below 2048-bit recommendation",
				Severity:    "medium",
			})
		}
	}

	// Insecure renegotiation — server's initial ServerHello does NOT carry the
	// RFC 5746 renegotiation_info extension. Patched servers always include
	// it, even if empty. Absence means the server is vulnerable to the 2009
	// Marsh-Ray TLS renegotiation MITM (CVE-2009-3555).
	if extPosture.Determined && !extPosture.SecureRenegotiation {
		vulns = append(vulns, tlsVuln{
			Name:        "Insecure renegotiation",
			CVE:         "CVE-2009-3555",
			Description: "no renegotiation_info — TLS renegotiation MITM",
			Severity:    "high",
		})
	}

	// CCS Injection — server didn't reject our out-of-order CCS record;
	// likely accepted it under a NULL master secret (CVE-2014-0224). Heuristic
	// — patched servers alert+close within ~milliseconds; we flag servers
	// that stay alive and silent past our 500 ms read deadline.
	if ccsInjection {
		vulns = append(vulns, tlsVuln{
			Name:        "CCS Injection",
			CVE:         "CVE-2014-0224",
			Description: "out-of-order ChangeCipherSpec accepted — NULL master secret MITM",
			Severity:    "high",
		})
	}

	// SWEET32 — 3DES negotiated, either in the main session or under TLS 1.0.
	if is3DESCipher(cipher) || is3DESCipher(tls10Cipher) {
		vulns = append(vulns, tlsVuln{
			Name:        "SWEET32",
			CVE:         "CVE-2016-2183",
			Description: "3DES (64-bit block) — birthday attack on long sessions",
			Severity:    "medium",
		})
	}

	// RC4 — vulnerable to plaintext recovery (CVE-2013-2566 / 2015-2808).
	// RFC 7465 explicitly prohibits RC4 in TLS.
	if isRC4Cipher(cipher) || isRC4Cipher(tls10Cipher) {
		vulns = append(vulns, tlsVuln{
			Name:        "RC4",
			CVE:         "CVE-2013-2566",
			Description: "RC4 cipher negotiated — prohibited by RFC 7465",
			Severity:    "high",
		})
	}

	// LUCKY13 — CBC ciphers in TLS 1.0-1.2 are theoretically vulnerable to a
	// timing side-channel on the MAC verification (CVE-2013-0169). We only
	// observe the cipher choice, not the timing; we label the surface here
	// without claiming a successful attack.
	if isCBCCipher(cipher) {
		vulns = append(vulns, tlsVuln{
			Name:        "LUCKY13",
			CVE:         "CVE-2013-0169",
			Description: "CBC cipher negotiated — exposed to MAC-timing side-channel",
			Severity:    "low",
		})
	}

	// BEAST — server accepts TLS 1.0 AND the cipher it picks under TLS 1.0 is
	// CBC mode. This is the actual BEAST precondition; checking the main
	// session's cipher alone would miss everything that supports TLS 1.3.
	if tls10Cipher != 0 && isCBCCipher(tls10Cipher) {
		vulns = append(vulns, tlsVuln{
			Name:        "BEAST",
			CVE:         "CVE-2011-3389",
			Description: "TLS 1.0 negotiates a CBC cipher — chosen-plaintext attack",
			Severity:    "medium",
		})
	}

	// POODLE — server still completes an SSLv3 handshake. Go's crypto/tls
	// removed SSLv3, so probeSSLv3 hand-rolls the ClientHello.
	if sslv3 {
		vulns = append(vulns, tlsVuln{
			Name:        "POODLE",
			CVE:         "CVE-2014-3566",
			Description: "SSLv3 accepted — padding oracle on CBC records",
			Severity:    "high",
		})
	}

	return vulns
}

// worstVulnerability returns the most severe vuln in the slice, or nil if
// empty. Ties are broken by slice order (so the first-detected wins).
func worstVulnerability(vulns []tlsVuln) *tlsVuln {
	if len(vulns) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(vulns); i++ {
		if vulns[i].severityRank() > vulns[best].severityRank() {
			best = i
		}
	}
	return &vulns[best]
}

// probeSSLv3 sends a minimal raw SSLv3 ClientHello and reports whether the
// server replies with an SSLv3-versioned handshake record. Servers that do
// are vulnerable to POODLE (CVE-2014-3566). Patched servers respond with a
// TLS alert (record type 0x15) or simply close the connection.
//
// We can't use crypto/tls for this — Go dropped SSLv3 support entirely. The
// ClientHello is therefore constructed byte-by-byte. We offer the cipher
// suites every real SSLv3-speaking server supports (RC4 + CBC).
func probeSSLv3(host string, port int, timeout time.Duration) bool {
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(sslv3ClientHello()); err != nil {
		return false
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	// 0x16 = handshake record. 0x15 = alert (server refused).
	if header[0] != 0x16 {
		return false
	}
	// Vulnerable iff the server agreed on SSL 3.0 (version bytes 0x03 0x00).
	return header[1] == 0x03 && header[2] == 0x00
}

// sslv3ClientHello returns a minimal raw SSLv3 ClientHello with a mix of CBC
// and RC4 cipher suites. SSLv3 predates extensions, so no SNI is sent — most
// SSLv3-speaking servers don't care about SNI anyway.
func sslv3ClientHello() []byte {
	cipherSuites := []uint16{
		0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x0004, // TLS_RSA_WITH_RC4_128_MD5
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}

	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	body := []byte{0x03, 0x00} // client_version = SSL 3.0
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression_methods: length=1, null

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)

	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x00, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// sctExtensionOID is the X.509 extension OID for embedded Signed Certificate
// Timestamps (RFC 6962 §3.3). Modern public CAs embed SCTs here rather than
// serving them via the TLS extension — so ConnectionState.SignedCertificateTimestamps
// is usually empty even on properly-CT-logged certs. countEmbeddedSCTs reads
// this extension to surface the real count.
var sctExtensionOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// countEmbeddedSCTs parses the X.509 SCT extension on a leaf cert and returns
// the number of SCTs embedded. Modern public CAs (Let's Encrypt, Sectigo,
// DigiCert, Cloudflare) all embed 2-3 SCTs from different CT logs; servers
// that surface SCTs only via the TLS extension are rare.
//
// The extension value is a TLS-format SignedCertificateTimestampList:
//
//	uint16 list_length
//	SerializedSCT[] sct_list   // each with its own uint16 length prefix
//
// Wrapped in an OCTET STRING per RFC 6962.
func countEmbeddedSCTs(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	for _, ext := range cert.Extensions {
		if !oidEqual(ext.Id, sctExtensionOID) {
			continue
		}
		return parseSCTList(ext.Value)
	}
	return 0
}

func oidEqual(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseSCTList counts entries in a TLS-format SignedCertificateTimestampList,
// optionally wrapped in an outer OCTET STRING (Go's x509 keeps the wrapper).
func parseSCTList(b []byte) int {
	// Strip outer OCTET STRING wrapper if present (0x04 tag).
	if len(b) >= 2 && b[0] == 0x04 {
		switch {
		case b[1] < 0x80:
			b = b[2:]
		case b[1] == 0x81 && len(b) >= 3:
			b = b[3:]
		case b[1] == 0x82 && len(b) >= 4:
			b = b[4:]
		}
	}
	if len(b) < 2 {
		return 0
	}
	listLen := int(b[0])<<8 | int(b[1])
	body := b[2:]
	if listLen > len(body) {
		return 0
	}
	body = body[:listLen]

	count := 0
	for i := 0; i+2 <= len(body); {
		sctLen := int(body[i])<<8 | int(body[i+1])
		i += 2
		if i+sctLen > len(body) {
			break
		}
		count++
		i += sctLen
	}
	return count
}

// isForwardSecret reports whether the cipher suite provides perfect forward
// secrecy. TLS 1.3 suites always do — the protocol mandates an ECDHE key
// exchange. TLS 1.2 and below provide FS only when the suite name starts with
// ECDHE_ or DHE_.
func isForwardSecret(suite uint16) bool {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return true
	}
	return false
}

// probeSessionResumption performs two TLS handshakes back-to-back through a
// shared ClientSessionCache and reports whether the second one resumed via
// the ticket from the first. For TLS 1.3 the NewSessionTicket arrives post-
// handshake, so we send a tiny request on the first connection to force the
// stack to process post-handshake messages before closing.
func probeSessionResumption(host string, port int, timeout time.Duration) bool {
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cache := tls.NewLRUClientSessionCache(2)
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
	}
	dialer := &net.Dialer{Timeout: timeout}

	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return false
	}
	// Drain the connection fully so any NewSessionTicket records (TLS 1.3
	// emits these post-handshake) get processed by Go's tls stack and land
	// in the session cache before we close. Reading once isn't enough — the
	// ticket can arrive interleaved with or after the response body.
	_ = conn1.SetDeadline(time.Now().Add(timeout))
	_, _ = io.WriteString(conn1, "GET / HTTP/1.0\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	for {
		if _, err := conn1.Read(buf); err != nil {
			break
		}
	}
	conn1.Close()

	conn2, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return false
	}
	defer conn2.Close()
	return conn2.ConnectionState().DidResume
}

// probeFallbackSCSV checks whether the server enforces TLS_FALLBACK_SCSV
// (RFC 7507) — the signal a client sends to ask the server to refuse a
// version downgrade. A properly-configured server, on receiving a ClientHello
// pinned to a version below its maximum AND containing cipher 0x5600, replies
// with alert 86 (inappropriate_fallback). A server that completes the
// handshake instead is missing the protection.
//
// Returns (protected, conclusive). conclusive=false means we couldn't tell
// (network error, weird alert, etc.) and the caller should treat it as N/A.
func probeFallbackSCSV(host string, port int, maxVersion uint16, timeout time.Duration) (protected bool, conclusive bool) {
	if maxVersion <= tls.VersionTLS10 {
		// No higher version to fall back from; SCSV doesn't apply.
		return true, false
	}
	fallbackVer := maxVersion - 1
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(fallbackSCSVClientHello(host, fallbackVer)); err != nil {
		return false, false
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false, false
	}
	recType := header[0]
	recLen := int(header[3])<<8 | int(header[4])
	if recLen < 2 || recLen > 1<<14 {
		return false, false
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return false, false
	}
	switch recType {
	case 0x15: // alert
		// alert: level(1), description(1). 86 = inappropriate_fallback.
		if body[1] == 86 {
			return true, true
		}
		// Other alerts: protocol_version (70), handshake_failure (40), etc.
		// We can't distinguish "rejected for SCSV reason" from "rejected for
		// some other reason that happens to also be safe", so be conservative.
		return false, false
	case 0x16: // handshake — server proceeded with the downgrade
		return false, true
	}
	return false, false
}

// fallbackSCSVClientHello builds a TLS ClientHello pinned to `ver` containing
// cipher suite 0x5600 (TLS_FALLBACK_SCSV) plus a small modern cipher list and
// an SNI extension. Used by probeFallbackSCSV.
func fallbackSCSVClientHello(host string, ver uint16) []byte {
	cipherSuites := []uint16{
		0x5600, // TLS_FALLBACK_SCSV (signal — not a real cipher)
		0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
		0xc030, // ECDHE_RSA_AES256_GCM_SHA384
		0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
		0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
		0xc013, // ECDHE_RSA_AES128_CBC_SHA
		0xc014, // ECDHE_RSA_AES256_CBC_SHA
		0x009c, // RSA_AES128_GCM_SHA256
		0x009d, // RSA_AES256_GCM_SHA384
		0x002f, // RSA_AES128_CBC_SHA
		0x0035, // RSA_AES256_CBC_SHA
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}

	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	extLen := len(extensions)

	body := []byte{byte(ver >> 8), byte(ver & 0xff)}
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)

	hsLen := len(hs)
	rec := []byte{0x16, byte(ver >> 8), byte(ver & 0xff), byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// probeHeartbleed sends a malicious TLS Heartbeat request and reports
// whether the server bleeds back data beyond what we sent. Implements
// CVE-2014-0160. Patched OpenSSL refuses to reply (or sends an alert);
// vulnerable OpenSSL returns up to 64 KB of process memory because it
// trusts the request's stated payload length over the actual payload.
//
// The ClientHello must include the Heartbeat extension (RFC 6520) so the
// server knows the client wants to send heartbeats. We then skip past the
// server's handshake messages until ServerHelloDone, then send the booby-
// trapped request: a Heartbeat record with payload_length=0x4000 but only
// 1 byte of actual payload.
func probeHeartbleed(host string, port int, timeout time.Duration) bool {
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(heartbleedClientHello(host)); err != nil {
		return false
	}
	if !skipToServerHelloDone(conn) {
		return false
	}

	// Malicious Heartbeat Request:
	//   record header: type=0x18 heartbeat, version=0x0302 (TLS 1.1), length=0x0003
	//   payload: type=0x01 (heartbeat_request), payload_length=0x4000 (lie!), data=(empty)
	// We claim 16384 bytes of payload but send none — vulnerable OpenSSL
	// trusts the claim and reads/replies with that many bytes of adjacent
	// memory.
	malicious := []byte{
		0x18, 0x03, 0x02, 0x00, 0x03,
		0x01,
		0x40, 0x00,
	}
	if _, err := conn.Write(malicious); err != nil {
		return false
	}

	// Read the response record header. A vulnerable server replies with a
	// Heartbeat record whose declared length exceeds what we sent.
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	recType := header[0]
	recLen := int(header[3])<<8 | int(header[4])
	if recType == 0x15 {
		// Alert — patched server refused.
		return false
	}
	// Heartbeat record (type 0x18) with payload way bigger than what we sent.
	// Patched servers either don't reply or send a 0-length heartbeat record
	// (~19 bytes with padding); vulnerable ones bleed back up to ~16 KB. A
	// 64-byte threshold leaves comfortable margin in both directions.
	return recType == 0x18 && recLen > 64
}

// skipToServerHelloDone reads TLS records from conn, parsing handshake
// messages inside, until it sees a ServerHelloDone (handshake type 0x0E).
// Returns true on success, false on read error or alert.
func skipToServerHelloDone(conn net.Conn) bool {
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return false
		}
		recType := header[0]
		recLen := int(header[3])<<8 | int(header[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return false
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return false
		}
		if recType == 0x15 {
			return false // alert
		}
		if recType != 0x16 {
			continue
		}
		// Walk handshake messages within this record. A single TLS record may
		// pack multiple handshake messages, and a single handshake message may
		// span records — but ServerHello/Certificate/ServerHelloDone all fit
		// within a single record in practice, so we don't handle the span case.
		i := 0
		for i+4 <= len(body) {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			if hsType == 0x0E { // ServerHelloDone
				return true
			}
			i += 4 + hsLen
			if i > len(body) {
				break
			}
		}
	}
}

// heartbleedClientHello builds a TLS 1.1 ClientHello with SNI and the
// Heartbeat extension. The cipher list is broad enough that any TLS-1.1-
// speaking server accepts it.
func heartbleedClientHello(host string) []byte {
	cipherSuites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c, // ECDHE_RSA/ECDSA AES-GCM
		0xc013, 0xc014, 0xc009, 0xc00a, // ECDHE CBC
		0x009c, 0x009d, // RSA AES-GCM
		0x002f, 0x0035, // RSA AES-CBC
		0x000a, // 3DES (legacy compat)
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}

	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	// Heartbeat extension (RFC 6520): type=0x000F, length=1, value=0x01
	// (peer_allowed_to_send).
	extensions = append(extensions, 0x00, 0x0f, 0x00, 0x01, 0x01)
	extLen := len(extensions)

	body := []byte{0x03, 0x02} // client_version = TLS 1.1
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)

	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x02, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// probeExportCiphers sends a TLS 1.0 ClientHello offering only the supplied
// cipher list. If the server completes ServerHello, it accepted one of these
// ciphers — used by the FREAK (RSA_EXPORT) and Logjam (DHE_EXPORT) probes.
// Returns true when the server agreed to a handshake with the given ciphers.
func probeExportCiphers(host string, port int, ciphers []uint16, timeout time.Duration) bool {
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(exportClientHello(host, ciphers)); err != nil {
		return false
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	// Handshake record (type 0x16) means the server picked one of our EXPORT
	// ciphers and is continuing — vulnerable. Alert (0x15) means refusal.
	return header[0] == 0x16
}

// exportClientHello builds a TLS 1.0 ClientHello carrying only the provided
// cipher suites. Used to detect FREAK and Logjam.
func exportClientHello(host string, ciphers []uint16) []byte {
	cipherBytes := make([]byte, 0, len(ciphers)*2)
	for _, c := range ciphers {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	extensions := buildSNIExtension(host)
	extLen := len(extensions)

	body := []byte{0x03, 0x01} // TLS 1.0
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x01, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// probeFREAK detects CVE-2015-0204 — server accepts an RSA_EXPORT cipher
// (40/56-bit RSA key exchange). Vulnerable servers let MITM downgrade to
// factorable RSA keys.
func probeFREAK(host string, port int, timeout time.Duration) bool {
	freakCiphers := []uint16{
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
		0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA (some impls)
		0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
		0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
	}
	return probeExportCiphers(host, port, freakCiphers, timeout)
}

// probeLogjam detects CVE-2015-4000 — server accepts a DHE_EXPORT cipher
// (512-bit DH parameters). Vulnerable servers let MITM downgrade to weak DH
// groups crackable with precomputation.
func probeLogjam(host string, port int, timeout time.Duration) bool {
	logjamCiphers := []uint16{
		0x000b, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
		0x000d, // TLS_DH_DSS_WITH_DES_CBC_SHA (legacy)
		0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
		0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
	}
	return probeExportCiphers(host, port, logjamCiphers, timeout)
}

// probeSSLv2 sends a raw SSLv2 ClientHello and reports whether the server
// completes an SSLv2 handshake exchange. Servers that do are vulnerable to
// DROWN (CVE-2016-0800) and to numerous earlier SSLv2-specific attacks.
//
// SSLv2 uses a completely different wire format from SSLv3/TLS:
//   length:  2 or 3 bytes (top bit of first byte = no-padding marker)
//   payload: msg-type (1B) + version (2B) + cipher-specs-length (2B) +
//            session-id-length (2B) + challenge-length (2B) +
//            cipher-specs (3B each) + session-id + challenge
// We send a tiny ClientHello and look for a length-prefixed SERVER-HELLO
// (msg-type 0x04) reply.
func probeSSLv2(host string, port int, timeout time.Duration) bool {
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(sslv2ClientHello()); err != nil {
		return false
	}

	// Read up to 5 bytes — enough to peek the length prefix and the first
	// byte of the message body. SSLv2 SERVER-HELLO starts with msg-type 0x04.
	buf := make([]byte, 5)
	n, err := io.ReadAtLeast(conn, buf, 3)
	if err != nil || n < 3 {
		return false
	}

	// Decode the length prefix:
	//   top bit of buf[0] set → 2-byte length, msg starts at buf[2]
	//   top bit clear        → 3-byte length, msg starts at buf[3]
	var msgStart int
	if buf[0]&0x80 != 0 {
		msgStart = 2
	} else {
		msgStart = 3
	}
	if n <= msgStart {
		return false
	}
	// Vulnerable iff the first message-body byte is 0x04 (SERVER-HELLO).
	return buf[msgStart] == 0x04
}

// sslv2ClientHello builds a minimal SSLv2 CLIENT-HELLO byte stream offering a
// mix of the classic SSLv2 cipher suites. We use the 2-byte-length encoding
// (top bit set) for simplicity. Challenge is random.
func sslv2ClientHello() []byte {
	// SSLv2 cipher specs (3 bytes each).
	specs := []byte{
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	}
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)

	// Message body
	body := []byte{
		0x01,       // msg-type: CLIENT-HELLO
		0x00, 0x02, // version: SSLv2 (0x0002)
		byte(len(specs) >> 8), byte(len(specs) & 0xff), // cipher-specs-length
		0x00, 0x00,                                     // session-id-length: 0
		byte(len(challenge) >> 8), byte(len(challenge) & 0xff), // challenge-length
	}
	body = append(body, specs...)
	body = append(body, challenge...)

	// 2-byte length prefix (top bit set, length = body length).
	out := []byte{0x80 | byte(len(body)>>8), byte(len(body) & 0xff)}
	return append(out, body...)
}

// probeCCSInjection detects CVE-2014-0224 — early ChangeCipherSpec acceptance.
// A vulnerable OpenSSL server accepts an out-of-order ChangeCipherSpec, runs
// the key schedule with an empty master_secret, and continues the handshake
// using NULL-derived MAC + AES keys. A patched server rejects the early CCS
// with unexpected_message alert(10) before ever computing keys.
//
// This is the cryptographic, testssl.sh-class detection — not a timing
// heuristic. We construct the exact Finished message the vulnerable server
// would expect from us under the NULL master_secret, encrypt it with the
// derived keys, and submit it. The server's response disambiguates:
//
//   - Server's own encrypted Finished (record type 0x16)  → VULNERABLE
//     (only possible if the server derived the same NULL keys and
//     decrypted+verified our Finished successfully)
//   - TLS alert (record type 0x15)                        → PATCHED
//   - Connection closed / silent                          → PATCHED
//
// Scope: TLS 1.2 + TLS_RSA_WITH_AES_128_CBC_SHA only. That's the smallest
// cipher offer with deterministic key sizes and HMAC-SHA1 record protection.
// The probe skips when the server refuses to negotiate this cipher (modern
// servers that only do AEAD / TLS 1.3).
func probeCCSInjection(host string, port int, timeout time.Duration) bool {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build a TLS 1.2 ClientHello offering only TLS_RSA_WITH_AES_128_CBC_SHA
	// (0x002F) so we know exactly which cipher to derive keys for.
	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)
	hello := ccsClientHello(host, clientRandom)

	// Track the handshake message bytes for the transcript hash. The
	// transcript covers ClientHello + ServerHello + Certificate +
	// (ServerKeyExchange — none for RSA) + ServerHelloDone, each as
	// its handshake-message body (1 byte type + 3 byte length + body).
	transcript := []byte{}
	// helloRecord = 5-byte record header + handshake message bytes.
	helloHandshakeBytes := hello[5:]
	transcript = append(transcript, helloHandshakeBytes...)

	if _, err := conn.Write(hello); err != nil {
		return false
	}

	// Walk server records until we see ServerHelloDone (handshake type 0x0E).
	// Capture handshake-message bytes for the transcript; capture ServerHello
	// to extract server_random and confirm cipher selection.
	var serverRandom []byte
	var negotiatedCipher uint16
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return false
		}
		if hdr[0] == 0x15 {
			return false // alert during handshake → server refused our offer
		}
		if hdr[0] != 0x16 {
			return false
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return false
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return false
		}
		transcript = append(transcript, body...)

		// Parse handshake messages inside this record.
		done := false
		for i := 0; i+4 <= len(body); {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			if i+4+hsLen > len(body) {
				break
			}
			hsBody := body[i+4 : i+4+hsLen]
			switch hsType {
			case 0x02: // ServerHello
				if len(hsBody) >= 38 {
					serverRandom = append(serverRandom, hsBody[2:34]...)
					sidLen := int(hsBody[34])
					if 35+sidLen+2 <= len(hsBody) {
						negotiatedCipher = uint16(hsBody[35+sidLen])<<8 | uint16(hsBody[35+sidLen+1])
					}
				}
			case 0x0E: // ServerHelloDone
				done = true
			}
			i += 4 + hsLen
		}
		if done {
			break
		}
	}

	// Skip when the server didn't pick our cipher. Modern servers often
	// refuse TLS_RSA_WITH_AES_128_CBC_SHA outright. In that case we either
	// already returned (alert / connection drop) or we'd be deriving keys
	// for a cipher the server didn't agree to.
	if negotiatedCipher != 0x002F || len(serverRandom) != 32 {
		return false
	}

	// Inject the out-of-order ChangeCipherSpec — the trigger record.
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	if _, err := conn.Write(ccs); err != nil {
		return false
	}

	// Derive the NULL-master-secret key block + verify_data for our
	// Finished. master_secret is 48 zero bytes by definition of the bug.
	masterSecret := make([]byte, 48)
	keys := deriveKeysAES128CBCSHA(masterSecret, serverRandom, clientRandom)

	transcriptHash := sha256.Sum256(transcript)
	verifyData := finishedVerifyData(masterSecret, transcriptHash[:])

	// Build Finished plaintext: handshake_type(0x14) || length(0x00000c) || verify_data.
	finishedPlain := []byte{0x14, 0x00, 0x00, 0x0c}
	finishedPlain = append(finishedPlain, verifyData...)

	iv := make([]byte, 16)
	_, _ = rand.Read(iv)

	recordBody, err := encryptRecordAES128CBCSHA(finishedPlain, keys, 0x16, 0x0303, 0, iv)
	if err != nil {
		return false
	}
	finishedRecord := []byte{0x16, 0x03, 0x03, byte(len(recordBody) >> 8), byte(len(recordBody) & 0xff)}
	finishedRecord = append(finishedRecord, recordBody...)
	if _, err := conn.Write(finishedRecord); err != nil {
		return false
	}

	// Read the server's response. The decisive signal:
	//   record type 0x16 (handshake) → vulnerable (server's own encrypted Finished)
	//   record type 0x15 (alert) or read error → patched
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	respHdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return false
	}
	return respHdr[0] == 0x16
}

// ccsClientHello builds the specific ClientHello used by probeCCSInjection:
// TLS 1.2, single cipher offer (TLS_RSA_WITH_AES_128_CBC_SHA), SNI extension.
// Returns the full record bytes; the first 5 bytes are the record header,
// the remainder is the handshake message ready for transcript hashing.
func ccsClientHello(host string, clientRandom []byte) []byte {
	cipherBytes := []byte{0x00, 0x2f} // TLS_RSA_WITH_AES_128_CBC_SHA only
	extensions := buildSNIExtension(host)
	extLen := len(extensions)

	body := []byte{0x03, 0x03} // client_version = TLS 1.2
	body = append(body, clientRandom...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)

	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// probeCRIME detects CVE-2012-4929 — TLS compression enabled at the server.
// Sends a TLS 1.2 ClientHello with compression_methods=[DEFLATE, null]; if
// the ServerHello's chosen compression_method byte is non-zero, the server
// agreed to compress and is CRIME-vulnerable.
//
// TLS 1.3 removed compression entirely (RFC 8446 §4.1.2 mandates compression
// method = null), so this probe returns false on TLS-1.3-only servers.
// Go's crypto/tls also never offers DEFLATE, so we hand-roll the ClientHello.
func probeCRIME(host string, port int, timeout time.Duration) bool {
	if timeout > 800*time.Millisecond {
		timeout = 800 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(crimeClientHello(host)); err != nil {
		return false
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	if header[0] != 0x16 {
		return false // alert or other; treat as not-vulnerable
	}
	recLen := int(header[3])<<8 | int(header[4])
	if recLen < 6 || recLen > 1<<14 {
		return false
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return false
	}

	// Walk handshake messages for ServerHello (type 0x02).
	i := 0
	for i+4 <= len(body) {
		hsType := body[i]
		hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
		hsEnd := i + 4 + hsLen
		if hsEnd > len(body) {
			break
		}
		if hsType == 0x02 { // ServerHello
			return serverHelloCompressionByte(body[i+4:hsEnd]) != 0
		}
		i = hsEnd
	}
	return false
}

// serverHelloCompressionByte extracts the compression_method byte from a
// ServerHello message body, or 0xff on parse failure (treated as "unknown,
// not vulnerable" by callers).
func serverHelloCompressionByte(body []byte) byte {
	// version(2) + random(32) + session_id_len(1) + session_id(N) +
	//   cipher_suite(2) + compression_method(1)
	if len(body) < 35 {
		return 0xff
	}
	sidLen := int(body[34])
	off := 35 + sidLen + 2 // skip session_id + cipher_suite
	if off >= len(body) {
		return 0xff
	}
	return body[off]
}

// crimeClientHello builds a TLS 1.2 ClientHello with compression_methods
// containing both DEFLATE (0x01) and null (0x00). Patched servers always
// pick null; vulnerable ones pick DEFLATE.
func crimeClientHello(host string) []byte {
	cipherSuites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c, // ECDHE GCM
		0xc013, 0xc014, 0xc009, 0xc00a, // ECDHE CBC
		0x009c, 0x009d, // RSA GCM
		0x002f, 0x0035, // RSA CBC
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	extensions := buildSNIExtension(host)
	extLen := len(extensions)

	body := []byte{0x03, 0x03} // client_version = TLS 1.2
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	// compression_methods: length=2, [DEFLATE=0x01, null=0x00]
	body = append(body, 0x02, 0x01, 0x00)
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// buildSNIExtension returns the bytes for a server_name (type 0) extension,
// containing one host_name entry for the given hostname.
func buildSNIExtension(host string) []byte {
	hostBytes := []byte(host)
	// Inner: name_type(1) + name_length(2) + name(N)
	inner := []byte{0x00, byte(len(hostBytes) >> 8), byte(len(hostBytes) & 0xff)}
	inner = append(inner, hostBytes...)
	// server_name_list length(2) + inner
	list := []byte{byte(len(inner) >> 8), byte(len(inner) & 0xff)}
	list = append(list, inner...)
	// Extension type(2) + extension data length(2) + extension data
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list) & 0xff)}
	return append(ext, list...)
}
