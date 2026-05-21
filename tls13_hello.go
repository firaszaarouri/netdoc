package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// TLS 1.3 ClientHello builder + ServerHello parser, scoped to what the
// 0-RTT detection probe needs:
//
//   - Single cipher suite: TLS_AES_128_GCM_SHA256 (0x1301), mandatory-to-
//     implement per RFC 8446. Offering only this keeps our key-schedule
//     simple (SHA-256, AES-128-GCM) and forces the server to either accept
//     it or abort — we don't need to handle ChaCha20 or 256-bit fallback.
//
//   - Single named group: x25519 (0x001d). Go's stdlib `crypto/ecdh.X25519`
//     gives us the ECDH machinery; offering only x25519 means the server
//     either matches or aborts, and our key_share computation is simple.
//
//   - Signature algorithms: a broad enough offer that the server doesn't
//     abort — we include rsa_pss_rsae_sha256 / ecdsa_secp256r1_sha256 /
//     rsa_pkcs1_sha256. We don't verify the cert anyway (this is a probe).
//
//   - PSK: none. We're probing fresh handshakes, not 0-RTT resumption.
//
//   - ALPN: not offered. Avoids accidentally negotiating an h2 / h3 path
//     that changes the server's NST behavior.
//
//   - server_name: required — most modern servers (Cloudflare, AWS ALB,
//     Akamai) refuse to handshake without SNI.

// TLS 1.3 cipher suite IDs (we only use the first).
const (
	tls13CipherAES128GCMSHA256 = 0x1301
	// tls13CipherAES256GCMSHA384 = 0x1302  // not offered
	// tls13CipherChaCha20Poly1305SHA256 = 0x1303  // not offered
)

// TLS extension type IDs (RFC 8446 §4.2).
const (
	extServerName        = 0
	extSupportedGroups   = 10
	extSignatureAlgos    = 13
	extALPN              = 16
	extSupportedVersions = 43
	extPSKKeyExchModes   = 45
	extKeyShare          = 51
	extEarlyData         = 42 // RFC 8446 §4.2.10 (max_early_data_size in NST)
)

// TLS 1.3 named groups (RFC 8446 §4.2.7).
const (
	groupX25519 = 0x001d
)

// TLS 1.3 signature algorithms (RFC 8446 §4.2.3).
var clientSignatureAlgos = []uint16{
	0x0804, // rsa_pss_rsae_sha256
	0x0403, // ecdsa_secp256r1_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0503, // ecdsa_secp384r1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0603, // ecdsa_secp521r1_sha512
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
}

// TLS handshake message types (RFC 8446 §4).
const (
	hsClientHello         = 1
	hsServerHello         = 2
	hsNewSessionTicket    = 4
	hsEncryptedExtensions = 8
	hsCertificate         = 11
	hsCertificateRequest  = 13
	hsCertificateVerify   = 15
	hsFinished            = 20
)

// TLS record types.
const (
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHandshake        = 22
	recordApplicationData  = 23
)

// clientHelloMaterial bundles the inputs+outputs of buildClientHello so the
// caller can compute the transcript hash and ECDH later.
type clientHelloMaterial struct {
	bytes        []byte           // wire bytes (handshake message including 4-byte header)
	random       []byte           // 32-byte client random
	sessionID    []byte           // 32-byte legacy_session_id (random)
	x25519Priv   *ecdh.PrivateKey // for shared-secret derivation
	x25519Pub   []byte           // copy of x25519Priv.PublicKey().Bytes()
}

// buildClientHello assembles a TLS 1.3 ClientHello for the 0-RTT probe.
// `sni` is the SNI hostname; pass an empty string only for IP-literal
// targets (which Go's tls package warns against and which Cloudflare et al.
// refuse).
//
// Wire format (RFC 8446 §4.1.2):
//
//	struct {
//	    ProtocolVersion legacy_version = 0x0303;     // TLS 1.2 for record-layer compat
//	    Random random;                                // 32 bytes
//	    opaque legacy_session_id<0..32>;              // 32 random bytes (TLS 1.2 middlebox compat)
//	    CipherSuite cipher_suites<2..2^16-2>;
//	    opaque legacy_compression_methods<1..2^8-1>;  // {0}
//	    Extension extensions<8..2^16-1>;
//	} ClientHello;
func buildClientHello(sni string) (*clientHelloMaterial, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	sessionID := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		return nil, err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes() // 32 bytes for x25519

	// ClientHello body (everything after the 4-byte handshake header):
	body := make([]byte, 0, 512)
	// legacy_version = 0x0303
	body = append(body, 0x03, 0x03)
	// random
	body = append(body, random...)
	// legacy_session_id (32 bytes)
	body = append(body, 32)
	body = append(body, sessionID...)
	// cipher_suites — only TLS_AES_128_GCM_SHA256
	body = binary.BigEndian.AppendUint16(body, 2) // length
	body = binary.BigEndian.AppendUint16(body, tls13CipherAES128GCMSHA256)
	// legacy_compression_methods = {0}
	body = append(body, 1, 0)

	// Extensions:
	ext := make([]byte, 0, 256)

	// supported_versions = [0x0304]
	ext = appendExtension(ext, extSupportedVersions, []byte{
		2,          // SupportedVersions list length
		0x03, 0x04, // TLS 1.3
	})

	// supported_groups = [x25519]
	ext = appendExtension(ext, extSupportedGroups, []byte{
		0x00, 0x02, // NamedGroupList length = 2
		0x00, 0x1d, // x25519
	})

	// signature_algorithms
	sigAlgoBuf := make([]byte, 0, 2+2*len(clientSignatureAlgos))
	sigAlgoBuf = binary.BigEndian.AppendUint16(sigAlgoBuf, uint16(2*len(clientSignatureAlgos)))
	for _, sa := range clientSignatureAlgos {
		sigAlgoBuf = binary.BigEndian.AppendUint16(sigAlgoBuf, sa)
	}
	ext = appendExtension(ext, extSignatureAlgos, sigAlgoBuf)

	// key_share — one entry, x25519
	keyShareEntry := make([]byte, 0, 4+len(pub))
	keyShareEntry = binary.BigEndian.AppendUint16(keyShareEntry, groupX25519)
	keyShareEntry = binary.BigEndian.AppendUint16(keyShareEntry, uint16(len(pub)))
	keyShareEntry = append(keyShareEntry, pub...)
	ksBuf := make([]byte, 0, 2+len(keyShareEntry))
	ksBuf = binary.BigEndian.AppendUint16(ksBuf, uint16(len(keyShareEntry)))
	ksBuf = append(ksBuf, keyShareEntry...)
	ext = appendExtension(ext, extKeyShare, ksBuf)

	// psk_key_exchange_modes — sending an empty list would be a protocol
	// error if we also sent pre_shared_key; we don't send PSK so it's
	// optional. We include {1 = psk_dhe_ke} as a courtesy for servers
	// that resume tickets from prior connections — none expected here.
	ext = appendExtension(ext, extPSKKeyExchModes, []byte{1, 1})

	// server_name (SNI), only if non-empty
	if sni != "" {
		nameBytes := []byte(sni)
		sniBuf := make([]byte, 0, 5+len(nameBytes))
		// ServerNameList length (2 bytes) - we'll fill after assembling entry
		entry := make([]byte, 0, 3+len(nameBytes))
		entry = append(entry, 0) // name_type = host_name (0)
		entry = binary.BigEndian.AppendUint16(entry, uint16(len(nameBytes)))
		entry = append(entry, nameBytes...)
		sniBuf = binary.BigEndian.AppendUint16(sniBuf, uint16(len(entry)))
		sniBuf = append(sniBuf, entry...)
		ext = appendExtension(ext, extServerName, sniBuf)
	}

	// Append extensions block (with 2-byte length) to body.
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	// Wrap in handshake header: msg_type(1) + length(3) + body.
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, hsClientHello)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	return &clientHelloMaterial{
		bytes:      hs,
		random:     random,
		sessionID:  sessionID,
		x25519Priv: priv,
		x25519Pub:  pub,
	}, nil
}

// appendExtension appends one Extension(extType, data) tuple to ext.
func appendExtension(ext []byte, extType uint16, data []byte) []byte {
	ext = binary.BigEndian.AppendUint16(ext, extType)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
	ext = append(ext, data...)
	return ext
}

// parsedServerHello holds the bits we care about from the server's reply.
type parsedServerHello struct {
	random            []byte // 32 bytes
	cipherSuite       uint16
	x25519ServerPub   []byte // 32 bytes from server's key_share extension
	helloRetryRequest bool   // true if random matches the HRR sentinel
	bytes             []byte // raw handshake message bytes including 4-byte header (for transcript)
}

// hrrRandom is the magic ServerHello.random value that flags a
// HelloRetryRequest (RFC 8446 §4.1.3). If we see this, the server wants
// a different group and we abort the probe — handling HRR properly would
// double the LOC and we'd only need it for servers that don't accept x25519.
var hrrRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// parseServerHello reads one ServerHello handshake message from msg (the
// 4-byte-header-prefixed handshake message bytes) and extracts cipher suite
// + server's x25519 pubkey.
func parseServerHello(msg []byte) (*parsedServerHello, error) {
	if len(msg) < 4 || msg[0] != hsServerHello {
		return nil, errors.New("not a ServerHello")
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) < 4+bodyLen {
		return nil, errors.New("ServerHello: short body")
	}
	body := msg[4 : 4+bodyLen]

	// ServerHello body:
	//   ProtocolVersion legacy_version = 0x0303; (2)
	//   Random random; (32)
	//   opaque legacy_session_id_echo<0..32>; (1+N)
	//   CipherSuite cipher_suite; (2)
	//   uint8 legacy_compression_method = 0; (1)
	//   Extension extensions<6..2^16-1>;
	if len(body) < 2+32+1 {
		return nil, errors.New("ServerHello: truncated header")
	}
	off := 2 // skip legacy_version
	random := append([]byte(nil), body[off:off+32]...)
	off += 32
	sidLen := int(body[off])
	off++
	if off+sidLen+2+1 > len(body) {
		return nil, errors.New("ServerHello: truncated session_id")
	}
	off += sidLen
	cipherSuite := binary.BigEndian.Uint16(body[off:])
	off += 2
	// compression method
	off++ // ignore value (should be 0)
	if off+2 > len(body) {
		return nil, errors.New("ServerHello: missing extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+extLen > len(body) {
		return nil, errors.New("ServerHello: extensions truncated")
	}
	exts := body[off : off+extLen]

	out := &parsedServerHello{
		random:      random,
		cipherSuite: cipherSuite,
		bytes:       append([]byte(nil), msg[:4+bodyLen]...),
	}

	// HelloRetryRequest detection by magic random.
	hrr := true
	for i := 0; i < 32; i++ {
		if random[i] != hrrRandom[i] {
			hrr = false
			break
		}
	}
	out.helloRetryRequest = hrr

	// Walk extensions to find key_share with x25519.
	eo := 0
	for eo+4 <= len(exts) {
		etype := binary.BigEndian.Uint16(exts[eo:])
		eo += 2
		elen := int(binary.BigEndian.Uint16(exts[eo:]))
		eo += 2
		if eo+elen > len(exts) {
			return nil, errors.New("ServerHello: extension length overflow")
		}
		edata := exts[eo : eo+elen]
		eo += elen
		if etype == extKeyShare {
			// In ServerHello, key_share is a single KeyShareEntry:
			//   NamedGroup group;   (2)
			//   opaque key_exchange<1..2^16-1>; (2+N)
			if len(edata) < 4 {
				return nil, errors.New("ServerHello: key_share too short")
			}
			group := binary.BigEndian.Uint16(edata[:2])
			if group != groupX25519 {
				return nil, errors.New("ServerHello: server selected unsupported group")
			}
			klen := int(binary.BigEndian.Uint16(edata[2:4]))
			if 4+klen > len(edata) {
				return nil, errors.New("ServerHello: key_share length overflow")
			}
			out.x25519ServerPub = append([]byte(nil), edata[4:4+klen]...)
		}
	}

	if !out.helloRetryRequest && out.x25519ServerPub == nil {
		return nil, errors.New("ServerHello: missing x25519 key_share")
	}
	return out, nil
}
