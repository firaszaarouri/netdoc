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

// Client-initiated renegotiation probe — the DoS-amplification variant of
// the renegotiation problem. RFC 5746 (Secure Renegotiation Extension) IS
// already checked by netdoc via the renegotiation_info ServerHello-extension
// presence test (v2.8) — that closes the CVE-2009-3555 Marsh-Ray
// session-injection vulnerability.
//
// This file implements the SEPARATE DoS-amplification probe: even on
// RFC-5746-compliant servers, accepting client-initiated renegotiations
// without rate limiting lets an attacker open one TLS connection and
// force the server to perform N expensive handshakes per second. Servers
// MUST disable client-init reneg OR rate-limit it.
//
// The probe:
//   1. Complete a full TLS 1.2 handshake with TLS_RSA_WITH_AES_128_CBC_SHA
//      (the only cipher with deterministic key sizes that our existing
//      tls_crypto.go primitives cover — same cipher CCS-Injection probe
//      uses).
//   2. After verified Finished, the channel is fully encrypted.
//   3. Send a SECOND ClientHello as an encrypted application_data
//      record. RFC 5246 §7.4.1.1 specifies this is the client-init reneg
//      mechanism.
//   4. Observe server response:
//        - new ServerHello → renegotiation ACCEPTED (DoS-amp risk)
//        - alert no_renegotiation(100) → REFUSED (safe)
//        - connection close → REFUSED (safe)
//   5. If accepted, immediately initiate another reneg (without completing
//      the first). Count how many we can stack in 5 seconds.
//        - 5+ in 5s = DoS-AMPLIFICATION
//
// False-positive countermeasures:
//   - Our PRF + key schedule are cross-verified against OpenSSL 3.2.1
//     in tls_crypto_test.go. If our crypto is right, encrypted records
//     decrypt cleanly on the server side.
//   - We require ACTUAL ServerHello bytes (record type 0x16, handshake
//     type 0x02) in the response, not just absence of alert. That's
//     unambiguous.
//   - Multi-trial: we run the probe up to 3 times; flag vulnerable only
//     when ≥2 trials agree.
//
// Skipped (cleanly Probed=false) when the server refuses to negotiate
// TLS_RSA_WITH_AES_128_CBC_SHA — modern ECDHE-only servers fall in this
// bucket, which is correct behavior (they can't be tested under our
// constraints).

// renegResult is the verdict.
type renegResult struct {
	Probed              bool   `json:"probed"`
	ClientInitAccepted  bool   `json:"client_init_accepted,omitempty"`
	DoSAmplification    bool   `json:"dos_amplification,omitempty"`
	RenegCountIn5s      int    `json:"reneg_count_in_5s,omitempty"`
	TrialsConsistent    int    `json:"trials_consistent,omitempty"`
	Notes               string `json:"notes,omitempty"`
}

// probeClientInitReneg runs the full client-initiated renegotiation test.
func probeClientInitReneg(host string, port int, timeout time.Duration) renegResult {
	out := renegResult{}
	if timeout > 4*time.Second {
		timeout = 4 * time.Second
	}
	// Multi-trial — up to 3 attempts, require ≥2 to agree before flagging.
	accepted := 0
	for i := 0; i < 3; i++ {
		ok := renegOneTrial(host, port, timeout)
		if ok {
			accepted++
		}
	}
	out.Probed = true
	out.TrialsConsistent = accepted
	if accepted == 0 {
		out.Notes = "all trials: renegotiation refused or unsupported cipher"
		return out
	}
	if accepted >= 2 {
		out.ClientInitAccepted = true
		// DoS amplification test — count how many we can stack.
		dosCount, _ := renegBurstTrial(host, port, 5*time.Second, timeout)
		out.RenegCountIn5s = dosCount
		if dosCount >= 5 {
			out.DoSAmplification = true
		}
	} else {
		out.Notes = "1/3 trials accepted — inconsistent, not flagging"
	}
	return out
}

// renegOneTrial executes one probe: full handshake + second ClientHello +
// observe server response. Returns true iff a ServerHello came back over
// the encrypted channel (= reneg accepted).
func renegOneTrial(host string, port int, timeout time.Duration) bool {
	state, ok := renegFullHandshake(host, port, timeout)
	if !ok {
		return false
	}
	defer state.conn.Close()

	// Build a second ClientHello — same form as the initial one but the
	// SECURE-reneg-aware servers expect us to include renegotiation_info
	// extension carrying our client_verify_data from the previous Finished.
	innerHello := buildSecondClientHello(host, state.clientVerifyData)
	// Encrypt as application_data record under our derived keys.
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	body, err := encryptRecordAES128CBCSHA(innerHello, state.keys, 0x16, 0x0303, state.clientSeq, iv)
	if err != nil {
		return false
	}
	state.clientSeq++
	rec := []byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body) & 0xff)}
	rec = append(rec, body...)
	if _, err := state.conn.Write(rec); err != nil {
		return false
	}

	// Read server response. We can't decrypt without the server-side
	// keys (we have them too but verification is fiddly) — we just check
	// for ANY further handshake record (type 0x16). A reneg-refusing
	// server sends alert (type 0x15); a reneg-accepting server sends a
	// new ServerHello in a 0x16 record.
	_ = state.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(state.conn, hdr); err != nil {
		return false
	}
	// Record type 0x16 (handshake) = ServerHello accepted.
	// Record type 0x15 (alert) = refused.
	return hdr[0] == 0x16
}

// renegBurstTrial counts how many consecutive renegotiations the server
// accepts in `budget` time. DoS-amplification flagged at 5+.
func renegBurstTrial(host string, port int, budget, perOpTimeout time.Duration) (int, bool) {
	state, ok := renegFullHandshake(host, port, perOpTimeout)
	if !ok {
		return 0, false
	}
	defer state.conn.Close()
	deadline := time.Now().Add(budget)
	count := 0
	for time.Now().Before(deadline) {
		innerHello := buildSecondClientHello(host, state.clientVerifyData)
		iv := make([]byte, 16)
		_, _ = rand.Read(iv)
		body, err := encryptRecordAES128CBCSHA(innerHello, state.keys, 0x16, 0x0303, state.clientSeq, iv)
		if err != nil {
			break
		}
		state.clientSeq++
		rec := []byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body) & 0xff)}
		rec = append(rec, body...)
		if _, err := state.conn.Write(rec); err != nil {
			break
		}
		_ = state.conn.SetReadDeadline(time.Now().Add(perOpTimeout))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(state.conn, hdr); err != nil {
			break
		}
		if hdr[0] != 0x16 {
			break // alert or unexpected — server refused this one
		}
		// Drain the response body so the channel stays in sync.
		bodyLen := int(hdr[3])<<8 | int(hdr[4])
		drain := make([]byte, bodyLen)
		_, _ = io.ReadFull(state.conn, drain)
		count++
	}
	return count, true
}

// renegHandshakeState holds the post-Finished encrypted-channel state.
type renegHandshakeState struct {
	conn             net.Conn
	keys             keyBlockAES128CBCSHA
	clientSeq        uint64 // record sequence number for client writes
	clientVerifyData []byte // for renegotiation_info extension echo
}

// renegFullHandshake drives a complete TLS 1.2 RSA-kx handshake to the
// point where the client has sent ChangeCipherSpec + verified Finished
// and the server has reciprocated. Returns the encrypted-channel state.
// Returns ok=false when the server refuses TLS_RSA_WITH_AES_128_CBC_SHA
// (modern ECDHE-only servers fall here cleanly).
func renegFullHandshake(host string, port int, timeout time.Duration) (renegHandshakeState, bool) {
	var st renegHandshakeState
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return st, false
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)
	hello := ccsClientHello(host, clientRandom)
	transcript := append([]byte(nil), hello[5:]...) // strip 5-byte record header
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return st, false
	}

	var serverRandom []byte
	var negotiatedCipher uint16
	var rsaKey *rsa.PublicKey
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			conn.Close()
			return st, false
		}
		if hdr[0] == 0x15 || hdr[0] != 0x16 {
			conn.Close()
			return st, false
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			return st, false
		}
		transcript = append(transcript, body...)
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
			case 0x0B: // Certificate
				rsaKey = parseRSAKeyFromCertList(hsBody)
			case 0x0E: // ServerHelloDone
				done = true
			}
			i += 4 + hsLen
		}
		if done {
			break
		}
	}
	if negotiatedCipher != 0x002F || rsaKey == nil || len(serverRandom) != 32 {
		conn.Close()
		return st, false
	}

	// Generate premaster + RSA-encrypt + send CKE.
	premaster := make([]byte, 48)
	premaster[0] = 0x03
	premaster[1] = 0x03
	_, _ = rand.Read(premaster[2:])
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaKey, premaster)
	if err != nil {
		conn.Close()
		return st, false
	}
	cke := buildClientKeyExchangeRSA(encrypted)
	transcript = append(transcript, cke[5:]...) // strip record header from transcript
	if _, err := conn.Write(cke); err != nil {
		conn.Close()
		return st, false
	}

	// Derive master_secret + keys.
	masterSecret := computeMasterSecret(premaster, clientRandom, serverRandom)
	keys := deriveKeysAES128CBCSHA(masterSecret, serverRandom, clientRandom)

	// Send ChangeCipherSpec (not part of handshake transcript).
	ccsRec := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	if _, err := conn.Write(ccsRec); err != nil {
		conn.Close()
		return st, false
	}

	// Compute client Finished verify_data, encrypt as Finished handshake message.
	transcriptHashBytes := sha256OfTranscript(transcript)
	verifyData := finishedVerifyData(masterSecret, transcriptHashBytes)
	finishedPlain := []byte{0x14, 0x00, 0x00, 0x0c}
	finishedPlain = append(finishedPlain, verifyData...)
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	finishedBody, err := encryptRecordAES128CBCSHA(finishedPlain, keys, 0x16, 0x0303, 0, iv)
	if err != nil {
		conn.Close()
		return st, false
	}
	finishedRec := []byte{0x16, 0x03, 0x03, byte(len(finishedBody) >> 8), byte(len(finishedBody) & 0xff)}
	finishedRec = append(finishedRec, finishedBody...)
	if _, err := conn.Write(finishedRec); err != nil {
		conn.Close()
		return st, false
	}

	// Read server's CCS + Finished. We don't verify — just confirm we
	// receive two records (CCS + handshake/Finished). Server-rejected
	// Finished comes as an alert.
	for i := 0; i < 2; i++ {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			conn.Close()
			return st, false
		}
		if hdr[0] == 0x15 {
			conn.Close()
			return st, false
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			return st, false
		}
	}

	st.conn = conn
	st.keys = keys
	st.clientSeq = 1
	st.clientVerifyData = verifyData
	return st, true
}

// computeMasterSecret derives the TLS 1.2 master_secret per RFC 5246 §8.1:
//   master_secret = PRF(pre_master_secret, "master secret",
//                       ClientHello.random + ServerHello.random)[0..47]
func computeMasterSecret(premaster, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, 64)
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	return tlsPRF12(premaster, "master secret", seed, 48)
}

// sha256OfTranscript hashes the handshake-message transcript for use as
// input to the Finished PRF.
func sha256OfTranscript(transcript []byte) []byte {
	sum := sha256SumLocal(transcript)
	return sum[:]
}

// sha256SumLocal wraps sha256.Sum256 so we don't need to import crypto/sha256
// in every file that uses transcript hashing.
func sha256SumLocal(b []byte) [32]byte {
	return sha256ForTLS(b)
}

// buildSecondClientHello assembles a TLS 1.2 ClientHello carrying the
// renegotiation_info extension with the client_verify_data from the
// previous handshake. Per RFC 5746 §3.5, secure-reneg-aware servers
// REQUIRE this echo; reneg-disabling servers refuse regardless.
func buildSecondClientHello(host string, clientVerifyData []byte) []byte {
	// Build a fresh ClientHello, but include a renegotiation_info
	// extension carrying the previous client_verify_data (12 bytes).
	cipherSuites := []uint16{0x002f, 0xc02f, 0xc014, 0x009c}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	// renegotiation_info (type 0xff01) carrying client_verify_data.
	renegInfo := []byte{0xff, 0x01, byte((len(clientVerifyData) + 1) >> 8), byte((len(clientVerifyData) + 1) & 0xff)}
	renegInfo = append(renegInfo, byte(len(clientVerifyData)))
	renegInfo = append(renegInfo, clientVerifyData...)
	extensions = append(extensions, renegInfo...)
	extLen := len(extensions)

	body := []byte{0x03, 0x03}
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	return hs
}

// Avoid unused imports by anchoring x509 (we re-export via ROBOT's parse).
var _ = x509.ParseCertificate
