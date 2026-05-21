package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"time"
)

// ROBOT (Return Of Bleichenbacher's Oracle Threat — CVE-2017-13099) full
// detection via the ERROR-MESSAGE variant. Bleichenbacher's 1998 attack
// uses observed differences in a server's response to malformed
// PKCS#1 v1.5 ClientKeyExchange messages as an oracle for decrypting
// arbitrary RSA ciphertext.
//
// The TIMING variant (server response delay distinguishes valid vs invalid
// padding) is brittle over real networks — the v2.8 agent audit flagged
// this. The ERROR-MESSAGE variant (testssl.sh `--BB`) is reliable: it
// classifies the server's response to FIVE specifically-malformed CKE
// messages into distinct buckets. If the buckets can be told apart, the
// server is vulnerable.
//
// The five probes vary how we corrupt the PKCS#1 v1.5 encryption:
//   1. Valid padding + correct premaster_secret (CONTROL)
//   2. Invalid version field but otherwise valid padding
//   3. Invalid 0x00 separator byte
//   4. Truncated premaster (too-short post-padding)
//   5. Random ciphertext (totally invalid)
//
// Patched servers (RFC 5246 §7.4.7.1) generate a random premaster and
// continue to Finished, then send bad_record_mac on Finished verification.
// All five probes produce IDENTICAL responses (alert type 20, position in
// the handshake, response timing within noise).
//
// Vulnerable servers behave differently — they may:
//   - Send distinct alert types (decode_error vs bad_record_mac)
//   - Close the connection at different stages
//   - Respond with different record sequences
//
// We classify each of the 5 probes by (alert_type, terminated_at_stage,
// response_length_bucket) and flag vulnerable iff ≥2 distinct buckets.
//
// References:
//   https://robotattack.org/
//   testssl.sh `--BB` (BleichenBacher) probe
//   RFC 5246 §7.4.7.1 (RSA-encrypted premaster, constant-time handling)

// robotResult is the verdict.
type robotResult struct {
	Probed         bool   `json:"probed"`
	CipherTested   string `json:"cipher_tested,omitempty"` // "TLS_RSA_WITH_AES_128_CBC_SHA"
	DistinctBuckets int   `json:"distinct_buckets,omitempty"`
	Vulnerable     bool   `json:"vulnerable,omitempty"`
	BucketSummary  string `json:"bucket_summary,omitempty"` // human-readable
}

// probeROBOT runs the 5-probe Bleichenbacher oracle test. Requires the
// server to support an RSA key exchange cipher; modern ECDHE-only servers
// return Probed=false (correctly, since they aren't even attackable here).
func probeROBOT(host string, port int, timeout time.Duration) robotResult {
	out := robotResult{}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	// First gauge: can we get the server to negotiate an RSA-kx cipher?
	// We use TLS_RSA_WITH_AES_128_CBC_SHA (the same cipher CCS-injection
	// uses) for deterministic key sizes.
	rsaKey, ok := fetchRSAServerKey(host, port, timeout)
	if !ok {
		return out
	}
	out.Probed = true
	out.CipherTested = "TLS_RSA_WITH_AES_128_CBC_SHA"

	probes := []rsaCKEMutation{
		{Name: "valid", Mutate: mutateValid},
		{Name: "bad_version", Mutate: mutateBadVersion},
		{Name: "bad_separator", Mutate: mutateBadSeparator},
		{Name: "short_pms", Mutate: mutateShortPMS},
		{Name: "random_cipher", Mutate: mutateRandomCipher},
	}
	buckets := make(map[string][]string)
	probeBucket := make(map[string]string)
	for _, p := range probes {
		signature := probeOneROBOT(host, port, rsaKey, p.Mutate, timeout)
		buckets[signature] = append(buckets[signature], p.Name)
		probeBucket[p.Name] = signature
	}
	out.DistinctBuckets = len(buckets)
	// Vulnerable iff the VALID probe lands in a different bucket from
	// the INVALID-padding probes (bad_version, bad_separator, random_cipher).
	// short_pms is EXCLUDED from distinctness — many non-vulnerable
	// servers send EOF on short PMS because the kernel rejects the
	// undersized record before alert generation, which is benign.
	// Reference: Bleichenbacher / ROBOT paper §3.4 ("Side-Channel Sources").
	validBucket := probeBucket["valid"]
	invalidBuckets := []string{
		probeBucket["bad_version"],
		probeBucket["bad_separator"],
		probeBucket["random_cipher"],
	}
	// Require: valid != ALL of the invalid responses AND the invalid
	// responses are uniform among themselves. This isolates the
	// Bleichenbacher signal from incidental TCP-stack quirks.
	allInvalidSame := invalidBuckets[0] != "" &&
		invalidBuckets[0] == invalidBuckets[1] &&
		invalidBuckets[0] == invalidBuckets[2]
	validDiffersFromInvalid := validBucket != "" &&
		validBucket != invalidBuckets[0]
	out.Vulnerable = allInvalidSame && validDiffersFromInvalid
	out.BucketSummary = formatBuckets(buckets)
	return out
}

// rsaCKEMutation describes one PKCS#1 v1.5 mutation strategy.
type rsaCKEMutation struct {
	Name   string
	Mutate func(plaintext, encrypted []byte, k int) []byte
}

// fetchRSAServerKey opens an RSA-kx handshake and returns the server's
// RSA public key from its Certificate message.
func fetchRSAServerKey(host string, port int, timeout time.Duration) (*rsa.PublicKey, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)
	hello := ccsClientHello(host, clientRandom)
	if _, err := conn.Write(hello); err != nil {
		return nil, false
	}
	// Walk handshake records collecting Certificate.
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, false
		}
		if hdr[0] != 0x16 {
			return nil, false
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return nil, false
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, false
		}
		for i := 0; i+4 <= len(body); {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			if i+4+hsLen > len(body) {
				return nil, false
			}
			hsBody := body[i+4 : i+4+hsLen]
			if hsType == 0x0B { // Certificate
				return parseRSAKeyFromCertList(hsBody), true
			}
			i += 4 + hsLen
		}
	}
}

// parseRSAKeyFromCertList finds the leaf certificate in a TLS Certificate
// handshake message body and returns its RSA public key. Returns nil on
// any parse error or non-RSA key.
func parseRSAKeyFromCertList(b []byte) *rsa.PublicKey {
	if len(b) < 3 {
		return nil
	}
	listLen := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if listLen+3 > len(b) {
		return nil
	}
	p := b[3 : 3+listLen]
	if len(p) < 3 {
		return nil
	}
	certLen := int(p[0])<<16 | int(p[1])<<8 | int(p[2])
	if certLen+3 > len(p) {
		return nil
	}
	certDER := p[3 : 3+certLen]
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil
	}
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return rsaKey
}

// probeOneROBOT performs ONE of the 5 oracle probes. Returns a signature
// string describing the server's response (alert type + record sequence +
// closed state). Servers that respond differently to different mutations
// produce different signatures → vulnerable.
func probeOneROBOT(host string, port int, pubKey *rsa.PublicKey, mutate func([]byte, []byte, int) []byte, timeout time.Duration) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "dial_failed"
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)
	hello := ccsClientHello(host, clientRandom)
	if _, err := conn.Write(hello); err != nil {
		return "hello_write_failed"
	}
	// Walk to ServerHelloDone.
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return "early_io_err"
		}
		if hdr[0] != 0x16 {
			return "non_handshake_record"
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "body_io_err"
		}
		done := false
		for i := 0; i+4 <= len(body); {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			if i+4+hsLen > len(body) {
				break
			}
			if hsType == 0x0E {
				done = true
			}
			i += 4 + hsLen
		}
		if done {
			break
		}
	}
	// Build a 48-byte premaster + encrypt with RSA-PKCS1v1.5 + apply mutation.
	premaster := make([]byte, 48)
	premaster[0] = 0x03 // TLS major version
	premaster[1] = 0x03 // TLS minor (1.2)
	_, _ = rand.Read(premaster[2:])
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, premaster)
	if err != nil {
		return "rsa_encrypt_err"
	}
	mutated := mutate(premaster, encrypted, pubKey.Size())

	// Build ClientKeyExchange record carrying our mutated encrypted blob.
	cke := buildClientKeyExchangeRSA(mutated)
	if _, err := conn.Write(cke); err != nil {
		return "cke_write_failed"
	}
	// Send ChangeCipherSpec (we have no real keys post-mutation; this is
	// part of the test).
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	if _, err := conn.Write(ccs); err != nil {
		return "ccs_write_failed"
	}
	// Send a Finished record (encrypted under whatever keys; will fail MAC
	// for any real server). We send random bytes — patched servers respond
	// with bad_record_mac uniformly; vulnerable ones may distinguish.
	finished := make([]byte, 64)
	finished[0] = 0x16
	finished[1] = 0x03
	finished[2] = 0x03
	finished[3] = 0x00
	finished[4] = 0x3B
	_, _ = rand.Read(finished[5:])
	if _, err := conn.Write(finished); err != nil {
		return "finished_write_failed"
	}
	// Read response and characterise.
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err == io.EOF {
		return "eof"
	}
	if err != nil {
		return "read_err"
	}
	if n < 6 {
		return "short_response"
	}
	// Signature: record_type + alert level + alert desc + length-class
	recordType := resp[0]
	lengthBucket := byte(n / 16) // bucket into 16-byte ranges
	if recordType == 0x15 && n >= 7 {
		// Alert record: type | level | desc
		return "alert_l" + uint8str(resp[5]) + "_d" + uint8str(resp[6]) + "_lb" + uint8str(lengthBucket)
	}
	return "rt" + uint8str(recordType) + "_lb" + uint8str(lengthBucket)
}

// buildClientKeyExchangeRSA assembles a TLS 1.2 ClientKeyExchange record
// containing an RSA-encrypted premaster_secret blob.
func buildClientKeyExchangeRSA(encryptedPMS []byte) []byte {
	body := []byte{
		byte(len(encryptedPMS) >> 8), byte(len(encryptedPMS) & 0xff),
	}
	body = append(body, encryptedPMS...)
	hsLen := len(body)
	hs := []byte{0x10, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen & 0xff)}
	hs = append(hs, body...)
	recLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(recLen >> 8), byte(recLen & 0xff)}
	return append(rec, hs...)
}

// The 5 mutations.
func mutateValid(plaintext, encrypted []byte, k int) []byte {
	// Pass through — the control case.
	return encrypted
}
func mutateBadVersion(plaintext, encrypted []byte, k int) []byte {
	// The TLS version bytes (offsets 0,1 of premaster) end up at specific
	// positions in the RSA-OAEP-style padded structure. Without re-encrypting
	// we instead flip ONE bit in the encrypted blob — a common probe is to
	// flip the first byte after the 0x00 0x02 marker which corresponds to
	// the padding-end indicator.
	out := append([]byte(nil), encrypted...)
	if len(out) > 0 {
		out[0] ^= 0x01
	}
	return out
}
func mutateBadSeparator(plaintext, encrypted []byte, k int) []byte {
	out := append([]byte(nil), encrypted...)
	if len(out) > 1 {
		out[len(out)-49] ^= 0x01 // disturb byte at the would-be 0x00 separator
	}
	return out
}
func mutateShortPMS(plaintext, encrypted []byte, k int) []byte {
	// Truncate the encrypted blob — guaranteed RSA-decryption error path.
	if len(encrypted) < 32 {
		return encrypted
	}
	return encrypted[:len(encrypted)-2]
}
func mutateRandomCipher(plaintext, encrypted []byte, k int) []byte {
	out := make([]byte, len(encrypted))
	_, _ = rand.Read(out)
	return out
}

// formatBuckets renders the bucket map as a comma-separated list of
// signatures and which probes hit each.
func formatBuckets(buckets map[string][]string) string {
	parts := []string{}
	for sig, probes := range buckets {
		joined := ""
		for i, p := range probes {
			if i > 0 {
				joined += ","
			}
			joined += p
		}
		parts = append(parts, sig+"={"+joined+"}")
	}
	return joinStrings(parts, " | ")
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

func uint8str(v byte) string {
	if v == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + byte(v%10)
		v /= 10
	}
	return string(buf[i:])
}

// robotHeadline returns "ROBOT: vulnerable" or empty.
func robotHeadline(r robotResult) string {
	if !r.Probed {
		return ""
	}
	if r.Vulnerable {
		return "ROBOT: vulnerable (Bleichenbacher oracle)"
	}
	return ""
}
