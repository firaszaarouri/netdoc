package main

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Cipher-suite enumeration per TLS version — the table SSL Labs and sslyze
// build by handshaking with one cipher offered at a time and asking the
// server which it accepts. Each probe is a raw TLS ClientHello reusing the
// hand-rolled bytes we already use for FREAK/Logjam/CCS-Injection.
//
// We probe a curated set of ~35 IANA cipher suites covering everything
// real-world servers support: AEAD (GCM, ChaCha20-Poly1305), forward-
// secret (ECDHE/DHE), legacy (CBC, RSA-static), and the weak/historical
// ones (RC4, 3DES) that should be off.

// cipherInfo is what we want to surface per supported cipher.
type cipherInfo struct {
	Code      uint16 `json:"code"`           // IANA codepoint
	Name      string `json:"name"`           // tls.CipherSuiteName when known, else "0xNNNN"
	Grade     string `json:"grade"`          // A / B / C / F per the rubric below
	ForwardSecret bool `json:"forward_secret"`
	AEAD      bool   `json:"aead"`
	CBC       bool   `json:"cbc"`
	Export    bool   `json:"export"`
}

// cipherEnum maps a TLS version to the list of ciphers the server accepted.
type cipherEnum struct {
	TLSVersion string       `json:"tls_version"`
	Ciphers    []cipherInfo `json:"ciphers"`
	WorstGrade string       `json:"worst_grade"`
}

// candidateCiphersTLS12 is the curated TLS 1.0–1.2 cipher list. Selected to
// span every interesting category (AEAD vs CBC, ECDHE vs DHE vs RSA-static,
// RC4 / 3DES / EXPORT for historical detection).
var candidateCiphersTLS12 = []uint16{
	// ECDHE + AEAD
	0xc02f, 0xc030, 0xc02b, 0xc02c,
	0xcca8, 0xcca9,
	// ECDHE + CBC
	0xc013, 0xc014, 0xc009, 0xc00a, 0xc027, 0xc023,
	// DHE + AEAD
	0x009e, 0x009f, 0xccaa,
	// DHE + CBC
	0x0033, 0x0039, 0x0067, 0x006b,
	// RSA-static + AEAD
	0x009c, 0x009d,
	// RSA-static + CBC
	0x002f, 0x0035, 0x003c, 0x003d,
	// RC4 (CVE-2013-2566)
	0x0005, 0x0004, 0xc011, 0xc007,
	// 3DES (SWEET32)
	0x000a, 0xc012, 0xc008,
	// EXPORT (FREAK / Logjam)
	0x0003, 0x0008, 0x0014,
}

// candidateCiphersTLS13 — RFC 8446 mandatory + the two experimental CCM
// variants. TLS 1.3 ciphers are AEAD-only.
var candidateCiphersTLS13 = []uint16{
	0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
}

// enumerateCiphers probes every candidate cipher at the given TLS version.
// Concurrent across ciphers; bounded probe timeout so even 35 ciphers
// finishes inside ~1 second.
func enumerateCiphers(host string, port int, tlsVer uint16, candidates []uint16, timeout time.Duration) []cipherInfo {
	if timeout > 1*time.Second {
		timeout = 1 * time.Second
	}
	type result struct {
		cipher uint16
		ok     bool
	}
	out := make(chan result, len(candidates))
	sem := make(chan struct{}, 20) // cap concurrent dials
	var wg sync.WaitGroup
	for _, c := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(c uint16) {
			defer wg.Done()
			defer func() { <-sem }()
			ok := probeOneCipher(host, port, tlsVer, c, timeout)
			out <- result{cipher: c, ok: ok}
		}(c)
	}
	go func() { wg.Wait(); close(out) }()

	var supported []cipherInfo
	for r := range out {
		if !r.ok {
			continue
		}
		supported = append(supported, classifyCipher(r.cipher))
	}
	return supported
}

// probeOneCipher sends a ClientHello offering only `cipher` at the pinned
// TLS version. Returns true if the server completes ServerHello (i.e.,
// agreed to that cipher).
func probeOneCipher(host string, port int, tlsVer uint16, cipher uint16, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := singleCipherClientHello(host, tlsVer, cipher)
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	// We just need to see a handshake record (type 0x16) back. An alert
	// (type 0x15) means refusal.
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	return hdr[0] == 0x16
}

// singleCipherClientHello builds a minimal raw ClientHello offering exactly
// one cipher suite. For TLS 1.3 the supported_versions extension is added
// so the server picks 1.3 even though the legacy version field reads 0x0303.
func singleCipherClientHello(host string, tlsVer uint16, cipher uint16) []byte {
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)

	// supported_groups extension (type 10): every modern TLS server expects
	// to see what curves we'd accept. Offer x25519, secp256r1, secp384r1.
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)
	// signature_algorithms extension (type 13): offer a broad set so
	// ECDSA-cert servers accept our TLS 1.2 ClientHello. Includes RSA-PSS,
	// ECDSA over P-256/P-384, RSA PKCS#1, Ed25519.
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x08, 0x07, // ed25519
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x01, // rsa_pkcs1_sha384
		0x02, 0x01, // rsa_pkcs1_sha1
		0x02, 0x03, // ecdsa_sha1
	)

	// For TLS 1.3 we MUST advertise supported_versions; the legacy version
	// field still reads 0x0303 per RFC 8446.
	legacyVer := tlsVer
	if tlsVer == 0x0304 {
		legacyVer = 0x0303
		// supported_versions extension (type 43): 1-byte list len + 0x0304
		extensions = append(extensions, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
		// key_share extension (type 51): empty client key shares — server
		// will send HelloRetryRequest if it really needs one, which still
		// lets us observe "the cipher was accepted" via the first response.
		extensions = append(extensions, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00)
	}
	extLen := len(extensions)

	body := []byte{byte(legacyVer >> 8), byte(legacyVer & 0xff)}
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length = 0
	body = append(body, 0x00, 0x02, byte(cipher>>8), byte(cipher&0xff))
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, byte(legacyVer >> 8), byte(legacyVer & 0xff), byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// classifyCipher turns an IANA cipher codepoint into a cipherInfo with
// grade + flags. Grading rubric (matches Mozilla SSL Configuration
// Generator's modern/intermediate/old tiers):
//
//	A — TLS 1.3 AEAD, OR TLS 1.2 ECDHE+AEAD
//	B — DHE+AEAD, or ECDHE+CBC (forward-secret but legacy mode)
//	C — RSA-static (no PFS) with modern cipher
//	F — RC4, 3DES, EXPORT
func classifyCipher(c uint16) cipherInfo {
	info := cipherInfo{Code: c, Name: cipherCodeName(c)}
	switch c {
	// TLS 1.3 AEAD
	case 0x1301, 0x1302, 0x1303, 0x1304, 0x1305:
		info.AEAD = true
		info.ForwardSecret = true
		info.Grade = "A"
	// ECDHE + AEAD
	case 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9:
		info.AEAD = true
		info.ForwardSecret = true
		info.Grade = "A"
	// DHE + AEAD
	case 0x009e, 0x009f, 0xccaa:
		info.AEAD = true
		info.ForwardSecret = true
		info.Grade = "B"
	// ECDHE + CBC
	case 0xc013, 0xc014, 0xc009, 0xc00a, 0xc027, 0xc023:
		info.CBC = true
		info.ForwardSecret = true
		info.Grade = "B"
	// DHE + CBC
	case 0x0033, 0x0039, 0x0067, 0x006b:
		info.CBC = true
		info.ForwardSecret = true
		info.Grade = "B"
	// RSA-static + AEAD
	case 0x009c, 0x009d:
		info.AEAD = true
		info.Grade = "C"
	// RSA-static + CBC
	case 0x002f, 0x0035, 0x003c, 0x003d:
		info.CBC = true
		info.Grade = "C"
	// RC4
	case 0x0005, 0x0004, 0xc011, 0xc007:
		info.Grade = "F"
	// 3DES
	case 0x000a, 0xc012, 0xc008:
		info.CBC = true
		info.Grade = "F"
	// EXPORT
	case 0x0003, 0x0008, 0x0014:
		info.Export = true
		info.Grade = "F"
	default:
		info.Grade = "?"
	}
	return info
}

// cipherCodeName falls back to a "0xNNNN" hex string when crypto/tls
// doesn't recognise the codepoint (older 3DES/EXPORT/RC4 ciphers Go
// removed long ago).
func cipherCodeName(c uint16) string {
	known := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305",
		0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
		0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x0004: "TLS_RSA_WITH_RC4_128_MD5",
		0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	}
	if name, ok := known[c]; ok {
		return name
	}
	return "0x" + uint16HexString(c)
}

func uint16HexString(v uint16) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[(v>>12)&0xf], hexd[(v>>8)&0xf], hexd[(v>>4)&0xf], hexd[v&0xf]})
}
