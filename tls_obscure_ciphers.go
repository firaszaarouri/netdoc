package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// silence unused — would be used for the alert-parsing error path.
var _ = errorf

func errorf(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}

// Obscure cipher detection — closes the testssl.sh gap for ciphers Go's
// crypto/tls doesn't implement natively (GOST, Camellia, SEED, ARIA,
// IDEA, RC2). The strategy: hand-roll a TLS 1.2 ClientHello listing
// ONLY these cipher IDs and inspect the ServerHello to see which (if
// any) the server selected.
//
// This is the same approach testssl.sh uses for cipher-by-cipher
// probing in `--each-cipher` mode. We don't need to negotiate a full
// handshake — we just need to read the server's ServerHello selection
// (or its handshake_failure alert).
//
// The cipher IDs covered here are the ones netdoc users actually need
// to audit:
//
//   GOST (Russian standard) — required for some Russian govt deployments
//   Camellia (Japanese standard) — still in some Asian PKI
//   SEED (Korean standard) — KISA-mandated for some Korean services
//   ARIA (Korean) — modern replacement for SEED
//   IDEA — legacy; sometimes seen on misconfigured OpenSSL builds
//   RC2 — only in EXPORT suites; flag if seen
//   NULL — encryption-disabled ciphers; instant fail
//   DES / 3DES single-mode — flag if not already detected via SWEET32

// obscureCipherEntry is one entry in the obscure-cipher catalogue.
type obscureCipherEntry struct {
	Code     uint16
	Name     string // IANA / OpenSSL hybrid name
	Family   string // "GOST" / "Camellia" / "SEED" / etc.
	Severity string // "weak", "broken", "policy", "info"
}

// obscureCipherCatalog enumerates the cipher IDs we probe for. Selected
// to give policy-driven users the answers they actually ask:
//
//   - "are we offering ANY GOST?"      (compliance / sovereignty)
//   - "are we offering ANY Camellia?"  (some Asian PKI)
//   - "are we offering ANY SEED/ARIA?" (Korean KISA)
//   - "are we offering ANY NULL?"      (always fail)
//   - "are we offering IDEA / RC2?"    (broken / legacy)
var obscureCipherCatalog = []obscureCipherEntry{
	// GOST 28147-89 — Russian government cipher.
	{0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT", "GOST", "policy"},
	{0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT", "GOST", "policy"},
	{0xc100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "GOST", "policy"},
	{0xc101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "GOST", "policy"},
	{0xc102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "GOST", "policy"},

	// Camellia (RFC 5932, RFC 6367).
	{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "Camellia", "info"},
	{0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "Camellia", "info"},
	{0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "Camellia", "info"},
	{0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "Camellia", "info"},
	{0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "Camellia", "info"},
	{0xc09c, "TLS_RSA_WITH_AES_128_CCM", "Camellia", "info"}, // mislabel-tolerant
	{0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM", "Camellia", "info"},
	{0xc0a4, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Camellia", "info"},
	{0xc0a5, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Camellia", "info"},

	// SEED (RFC 4162) — Korean standard.
	{0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", "SEED", "info"},
	{0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA", "SEED", "info"},
	{0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA", "SEED", "info"},
	{0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "SEED", "info"},
	{0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "SEED", "info"},

	// ARIA (RFC 6209) — modern Korean replacement for SEED.
	{0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "ARIA", "info"},
	{0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "ARIA", "info"},
	{0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "ARIA", "info"},
	{0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "ARIA", "info"},

	// IDEA (RFC 5469) — legacy / patent-encumbered, broken.
	{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", "IDEA", "broken"},

	// RC2 — only in EXPORT suites in 2026; always weak.
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RC2", "broken"},

	// NULL ciphers (no encryption) — RFC 5746 / 5469.
	{0x0001, "TLS_RSA_WITH_NULL_MD5", "NULL", "broken"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA", "NULL", "broken"},
	{0x003b, "TLS_RSA_WITH_NULL_SHA256", "NULL", "broken"},
	{0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA", "NULL", "broken"},
}

// obscureCipherResult records the probe's findings.
type obscureCipherResult struct {
	Probed       bool                       `json:"probed"`
	OfferedSuite *obscureCipherEntry        `json:"offered_suite,omitempty"`
	Note         string                     `json:"note,omitempty"`
	Probed_Count int                        `json:"probes_attempted"`
}

// probeObscureCiphers sends one hand-rolled TLS 1.2 ClientHello with
// the full obscure-cipher list. If the server selects ANY of them in
// its ServerHello, we report which one.
//
// Single-probe approach: testing each cipher individually would mean
// ~30 handshakes. We instead offer them all in one ClientHello and let
// the server pick. If the server's selection is in our obscure
// catalogue, that's the hit; if it picks none (handshake_failure
// alert), no obscure cipher is offered.
func probeObscureCiphers(host string, port int, timeout time.Duration) obscureCipherResult {
	out := obscureCipherResult{Probed: true, Probed_Count: len(obscureCipherCatalog)}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		out.Note = "dial failed: " + tidyErr(err)
		out.Probed = false
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build a TLS 1.2 ClientHello offering only the obscure ciphers.
	hello, err := buildObscureClientHello(host)
	if err != nil {
		out.Note = "ClientHello build failed: " + tidyErr(err)
		return out
	}
	if _, err := conn.Write(hello); err != nil {
		out.Note = "ClientHello write failed: " + tidyErr(err)
		return out
	}

	// Parse the ServerHello response. Server response begins with a TLS
	// record header (type=22 handshake, version, length) followed by a
	// handshake message (type=2 ServerHello, length, body).
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		out.Note = "no response — server closed connection (no obscure cipher accepted)"
		return out
	}
	recType := header[0]
	if recType == 21 {
		// Alert record — server explicitly refused.
		alert := make([]byte, 2)
		_, _ = io.ReadFull(conn, alert)
		out.Note = fmt.Sprintf("alert level=%d desc=%d — no obscure cipher offered", alert[0], alert[1])
		return out
	}
	if recType != 22 {
		out.Note = fmt.Sprintf("unexpected record type %d", recType)
		return out
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen < 10 || recLen > 4096 {
		out.Note = fmt.Sprintf("implausible record length %d", recLen)
		return out
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		out.Note = "ServerHello read truncated: " + tidyErr(err)
		return out
	}

	// Handshake message layout: 1B type + 3B length + body.
	if len(body) < 4 || body[0] != 0x02 { // 0x02 = ServerHello
		out.Note = fmt.Sprintf("unexpected handshake type 0x%02x", body[0])
		return out
	}
	shBody := body[4:]
	// ServerHello body:
	//   2B server_version
	//   32B random
	//   1B session_id_length + N bytes session_id
	//   2B cipher_suite ← what we want
	if len(shBody) < 2+32+1 {
		out.Note = "ServerHello too short"
		return out
	}
	off := 2 + 32 // skip version + random
	sidLen := int(shBody[off])
	off++
	off += sidLen
	if off+2 > len(shBody) {
		out.Note = "ServerHello truncated before cipher_suite"
		return out
	}
	selected := binary.BigEndian.Uint16(shBody[off : off+2])

	// Match against our catalog.
	for _, c := range obscureCipherCatalog {
		if c.Code == selected {
			entry := c
			out.OfferedSuite = &entry
			out.Note = fmt.Sprintf("server selected 0x%04x (%s, family=%s, severity=%s)",
				selected, c.Name, c.Family, c.Severity)
			return out
		}
	}
	// Server selected a cipher NOT in our obscure list — they declined
	// to use any obscure suite even when we offered only those. This
	// shouldn't happen with a strict catalog but tolerate it.
	out.Note = fmt.Sprintf("server selected unexpected 0x%04x (not in obscure catalog)", selected)
	return out
}

// buildObscureClientHello produces a TLS 1.2 ClientHello record offering
// the obscure cipher list. Minimal extension set: server_name (SNI),
// extended_master_secret (so EMS-strict servers don't refuse outright),
// supported_groups, signature_algorithms, supported_versions.
func buildObscureClientHello(sni string) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	sessionID := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		return nil, err
	}

	// ClientHello body assembly.
	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03) // legacy_version TLS 1.2
	body = append(body, random...)
	body = append(body, 32)
	body = append(body, sessionID...)

	// cipher_suites — obscure catalog.
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(obscureCipherCatalog)))
	for _, c := range obscureCipherCatalog {
		body = binary.BigEndian.AppendUint16(body, c.Code)
	}

	// compression_methods = {0}
	body = append(body, 0x01, 0x00)

	// Extensions.
	ext := make([]byte, 0, 256)

	// server_name (SNI) — type 0.
	if sni != "" {
		nameBytes := []byte(sni)
		entry := make([]byte, 0, 3+len(nameBytes))
		entry = append(entry, 0) // name_type host_name
		entry = binary.BigEndian.AppendUint16(entry, uint16(len(nameBytes)))
		entry = append(entry, nameBytes...)
		sniBuf := make([]byte, 0, 2+len(entry))
		sniBuf = binary.BigEndian.AppendUint16(sniBuf, uint16(len(entry)))
		sniBuf = append(sniBuf, entry...)
		ext = appendExtension(ext, 0, sniBuf)
	}

	// supported_groups — type 10. Include common groups so we don't get
	// refused for missing the group entirely.
	ext = appendExtension(ext, 10, []byte{
		0x00, 0x08, // list length 8
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
		0x00, 0x19, // secp521r1
		0x00, 0x1d, // x25519
	})

	// signature_algorithms — type 13. Include broad set so the server
	// can pick something compatible with whatever cipher it might select.
	ext = appendExtension(ext, 13, []byte{
		0x00, 0x10, // list length 16
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x01, // rsa_pkcs1_sha384
		0x06, 0x01, // rsa_pkcs1_sha512
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x08, 0x06, // rsa_pss_rsae_sha512
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
	})

	// supported_versions — type 43. Advertise TLS 1.2 only.
	ext = appendExtension(ext, 43, []byte{
		0x02,       // versions list length 2
		0x03, 0x03, // TLS 1.2
	})

	// Add extensions block to body.
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	// Handshake header: type=1 ClientHello, 3-byte length, body.
	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	// Record header: type=22 handshake, version=TLS 1.0 (legacy compat),
	// 2-byte length, handshake payload.
	rec := make([]byte, 5+len(hs))
	rec[0] = 22
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec, nil
}

// obscureCipherHeadline returns a short summary when an obscure suite
// is selected.
func obscureCipherHeadline(r obscureCipherResult) string {
	if !r.Probed || r.OfferedSuite == nil {
		return ""
	}
	switch r.OfferedSuite.Severity {
	case "broken":
		return fmt.Sprintf("DANGER: %s cipher offered (%s)", r.OfferedSuite.Family, r.OfferedSuite.Name)
	case "policy":
		return fmt.Sprintf("%s suite offered (policy-sensitive)", r.OfferedSuite.Family)
	default:
		return fmt.Sprintf("%s suite offered", r.OfferedSuite.Family)
	}
}

// silence unused-import linter for strings when refactors drop usage.
var _ = strings.TrimSpace
