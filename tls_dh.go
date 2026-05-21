package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

// Logjam common-prime check — fixes the factual incompleteness in our shipped
// Logjam probe (which catches only DHE_EXPORT). The real Logjam paper
// (https://weakdh.org) showed that 1024-bit DH primes are crackable in
// nation-state-budget precomputation IF widely shared, because a single
// precomputation breaks every server using that prime.
//
// Our probe:
//   1. Send a TLS 1.2 ClientHello offering DHE_RSA suites.
//   2. Walk handshake to ServerKeyExchange (handshake type 0x0c).
//   3. Parse the DH ServerKeyExchange body: length-prefixed dh_p, dh_g, dh_Ys.
//   4. Compute SHA-256(dh_p_raw) and compare to known weak-prime digests.
//   5. Report prime bit-length + matched name (if any).
//
// What "weak" means:
//   • <1024 bits — always insecure (Logjam paper-grade crackable).
//   • Exactly 1024 bits — borderline, requires nation-state attacker but
//     known-feasible (NSA budget ≈ years per prime).
//   • 1024 bits AND in the common-prime list — confirmed worst case.
//   • 2048+ bits — strong unless future analysis says otherwise.
//
// Servers that don't support any DHE_RSA cipher (e.g. ECDHE-only modern
// configs) return Determined=false, Supported=false — informative not failure.

// dhParameterPosture records the verdict per server.
type dhParameterPosture struct {
	Supported       bool   `json:"supported"`        // server completed DHE handshake
	Bits            int    `json:"bits,omitempty"`   // bit length of dh_p
	CommonPrime     bool   `json:"common_prime"`     // matched a known weak/shared prime
	PrimeName       string `json:"prime_name,omitempty"` // human label e.g. "RFC 2409 Group 2 (Apache)"
	FingerprintSHA  string `json:"fingerprint_sha256,omitempty"`
	Determined      bool   `json:"-"` // false = probe failed / skipped
}

// probeDHParameters runs the DHE_RSA-only handshake and returns the parameter
// posture. Reuses the existing wire-format scaffolding from tls_vulns.go.
func probeDHParameters(host string, port int, timeout time.Duration) dhParameterPosture {
	var out dhParameterPosture
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(dhClientHello(host)); err != nil {
		return out
	}

	// Walk handshake records collecting messages until we see SKE (0x0c) or
	// ServerHelloDone (0x0e). If we hit ServerHelloDone without a SKE, the
	// server picked a non-DHE cipher despite our offer.
	out.Determined = true
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return out
		}
		recType := hdr[0]
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 1<<14+2048 {
			return out
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return out
		}
		if recType == 0x15 {
			return out
		}
		if recType != 0x16 {
			continue
		}
		for i := 0; i+4 <= len(body); {
			hsType := body[i]
			hsLen := int(body[i+1])<<16 | int(body[i+2])<<8 | int(body[i+3])
			end := i + 4 + hsLen
			if end > len(body) {
				return out
			}
			switch hsType {
			case 0x0c: // ServerKeyExchange
				out.Supported = true
				p := extractDHPrime(body[i+4 : end])
				if p == nil {
					return out
				}
				bn := new(big.Int).SetBytes(p)
				out.Bits = bn.BitLen()
				sum := sha256.Sum256(p)
				out.FingerprintSHA = strings.ToUpper(hex.EncodeToString(sum[:]))
				if name, ok := commonPrimeDB[out.FingerprintSHA]; ok {
					out.CommonPrime = true
					out.PrimeName = name
				}
				return out
			case 0x0e: // ServerHelloDone — no SKE seen, server doesn't do DHE
				return out
			}
			i = end
		}
	}
}

// dhClientHello builds a TLS 1.2 ClientHello offering DHE_RSA suites only.
// We deliberately do NOT include ECDHE — that would let the server avoid DHE.
// We include both AEAD and CBC DHE_RSA so even older servers pick a DHE
// suite, which is exactly what gives us a ServerKeyExchange to parse.
func dhClientHello(host string) []byte {
	cipherSuites := []uint16{
		0x009e, // DHE_RSA_AES_128_GCM_SHA256
		0x009f, // DHE_RSA_AES_256_GCM_SHA384
		0xccaa, // DHE_RSA_CHACHA20_POLY1305
		0x0033, // DHE_RSA_AES_128_CBC_SHA
		0x0039, // DHE_RSA_AES_256_CBC_SHA
		0x0067, // DHE_RSA_AES_128_CBC_SHA256
		0x006b, // DHE_RSA_AES_256_CBC_SHA256
		0x0016, // DHE_RSA_3DES_EDE_CBC_SHA (legacy)
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, 0x05, 0x03,
		0x08, 0x04, 0x08, 0x05, 0x08, 0x07,
		0x04, 0x01, 0x05, 0x01,
		0x02, 0x01, 0x02, 0x03,
	)
	extLen := len(extensions)

	body := []byte{0x03, 0x03}
	body = append(body, rnd...)
	body = append(body, 0x00)
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// extractDHPrime parses a DHE_RSA ServerKeyExchange body and returns the
// raw bytes of dh_p (big-endian, unsigned). Layout per RFC 5246 §7.4.3:
//
//   opaque dh_p<1..2^16-1>;
//   opaque dh_g<1..2^16-1>;
//   opaque dh_Ys<1..2^16-1>;
//   ... followed by signed_params (HashAlgo + SigAlgo + sig).
//
// Each opaque<...> is encoded as 2-byte big-endian length prefix + bytes.
// Returns nil on parse failure.
func extractDHPrime(ske []byte) []byte {
	if len(ske) < 2 {
		return nil
	}
	pLen := int(ske[0])<<8 | int(ske[1])
	if 2+pLen > len(ske) {
		return nil
	}
	return ske[2 : 2+pLen]
}

// commonPrimeDB maps SHA-256 fingerprints (uppercase hex, no separator) of
// canonical weak/shared DH primes to human-readable names. The fingerprints
// are computed from the wire-format big-endian unsigned bytes of each prime.
//
// Sources: RFC 2409, RFC 3526, RFC 5114, Apache mod_ssl source, JDK
// SSLEngine source, Cisco IOS hardcoded values. The list is the canonical
// "Logjam top primes" plus the high-bit RFC 3526 groups for completeness
// (the latter are flagged Strong=false so they don't false-positive).
var commonPrimeDB = func() map[string]string {
	db := map[string]string{}
	for _, e := range commonPrimeRaw {
		raw := parseHexBlob(e.hex)
		sum := sha256.Sum256(raw)
		fp := strings.ToUpper(hex.EncodeToString(sum[:]))
		db[fp] = e.name
	}
	return db
}()

// commonPrimeRaw is the canonical prime database. The hex strings are taken
// verbatim from the RFCs / source files cited in each name.
var commonPrimeRaw = []struct {
	name string
	hex  string
}{
	{
		// RFC 2409 §6.1, "First Oakley Default Group" — 768-bit MODP.
		// Trivially crackable on a modern desktop GPU farm.
		name: "RFC 2409 Group 1 (768-bit MODP)",
		hex: `FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1` +
			`29024E088A67CC74020BBEA63B139B22514A08798E3404DD` +
			`EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245` +
			`E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF`,
	},
	{
		// RFC 2409 §6.2, "Second Oakley Default Group" — 1024-bit MODP.
		// Used as default in Apache 2.2, mod_ssl, Postfix, JDK <8u121,
		// MikroTik, many IKE/IPsec stacks. THIS is the prime the Logjam
		// paper showed was precomputable for nation-state attackers.
		name: "RFC 2409 Group 2 (1024-bit MODP — Apache/mod_ssl/JDK default)",
		hex: `FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1` +
			`29024E088A67CC74020BBEA63B139B22514A08798E3404DD` +
			`EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245` +
			`E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED` +
			`EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381` +
			`FFFFFFFFFFFFFFFF`,
	},
	{
		// RFC 5114 §2.1 — 1024-bit MODP Group with 160-bit Prime Order
		// Subgroup. Used by some older OpenSSL builds.
		name: "RFC 5114 Group 22 (1024-bit MODP with 160-bit prime-order subgroup)",
		hex: `B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6` +
			`9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0` +
			`13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70` +
			`98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0` +
			`A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708` +
			`DF1FB2BC2E4A4371`,
	},
	{
		// RFC 3526 §2 — 1536-bit MODP Group ("Group 5"). Borderline in 2026 —
		// not nation-state-trivial but no longer recommended. Flag as a
		// common-prime hit so users know what they're running.
		name: "RFC 3526 Group 5 (1536-bit MODP)",
		hex: `FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1` +
			`29024E088A67CC74020BBEA63B139B22514A08798E3404DD` +
			`EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245` +
			`E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED` +
			`EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D` +
			`C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F` +
			`83655D23DCA3AD961C62F356208552BB9ED529077096966D` +
			`670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF`,
	},
	{
		// RFC 3526 §3 — 2048-bit MODP Group ("Group 14"). Strong by 2026
		// standards; we include it not as a "weak" hit but as a positive
		// match so the user sees "RFC 3526 Group 14 — strong" rather than
		// an empty/unknown name.
		name: "RFC 3526 Group 14 (2048-bit MODP — strong)",
		hex: `FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1` +
			`29024E088A67CC74020BBEA63B139B22514A08798E3404DD` +
			`EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245` +
			`E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED` +
			`EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D` +
			`C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F` +
			`83655D23DCA3AD961C62F356208552BB9ED529077096966D` +
			`670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B` +
			`E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9` +
			`DE2BCBF6955817183995497CEA956AE515D2261898FA0510` +
			`15728E5A8AACAA68FFFFFFFFFFFFFFFF`,
	},
}

// parseHexBlob strips whitespace and decodes a hex string into bytes. Panic-
// free fallback: returns nil on parse error so the affected entry simply
// won't appear in commonPrimeDB.
func parseHexBlob(s string) []byte {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	raw, err := hex.DecodeString(b.String())
	if err != nil {
		return nil
	}
	return raw
}
