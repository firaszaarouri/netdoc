package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// TLS 1.2 cryptographic primitives needed for the gold-standard CCS Injection
// probe in probeCCSInjectionCrypto. None of this would normally be needed —
// Go's crypto/tls handles all of it internally — but the CVE-2014-0224 probe
// has to construct a Finished message under a NULL master_secret, which means
// running the TLS PRF + key schedule + record protection by hand.
//
// Scope: TLS 1.2 only, AES-128-CBC + HMAC-SHA1 only (TLS_RSA_WITH_AES_128_CBC_SHA,
// cipher suite 0x002f). That's the smallest, most-stable cipher offer we
// can make to a vulnerable OpenSSL server, and it gives us deterministic
// key/MAC sizes for the schedule.

// tlsPRF12 is the TLS 1.2 PRF (RFC 5246 §5) using HMAC-SHA256. Returns
// exactly `length` bytes of output: P_SHA256(secret, label || seed).
func tlsPRF12(secret []byte, label string, seed []byte, length int) []byte {
	return phash(sha256.New, secret, append([]byte(label), seed...), length)
}

// phash implements TLS's P_hash construction (RFC 5246 §5):
//   A(0) = seed
//   A(i) = HMAC(secret, A(i-1))
//   P_hash = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
// truncated to the requested length.
func phash(h func() hash.Hash, secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	a := hmacOnce(h, secret, seed) // A(1)
	for len(out) < length {
		mac := hmac.New(h, secret)
		mac.Write(a)
		mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
		a = hmacOnce(h, secret, a)
	}
	return out[:length]
}

func hmacOnce(h func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(h, key)
	m.Write(data)
	return m.Sum(nil)
}

// keyBlockAES128CBCSHA holds the slices of the TLS 1.2 key block used by
// TLS_RSA_WITH_AES_128_CBC_SHA. Sizes per RFC 5246 / RFC 4346:
//   MAC key:        20 bytes  (SHA-1)
//   Encryption key: 16 bytes  (AES-128)
//   IV:              0 bytes  (TLS 1.1+ uses explicit IV per record)
type keyBlockAES128CBCSHA struct {
	ClientMAC []byte
	ServerMAC []byte
	ClientKey []byte
	ServerKey []byte
}

// deriveKeysAES128CBCSHA computes the AES-128-CBC + HMAC-SHA1 key block from
// the (deliberately empty in our case) master_secret, server_random and
// client_random. TLS 1.2 PRF, key-expansion label, total 72 bytes:
//   20 ClientMAC + 20 ServerMAC + 16 ClientKey + 16 ServerKey
func deriveKeysAES128CBCSHA(masterSecret, serverRandom, clientRandom []byte) keyBlockAES128CBCSHA {
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	block := tlsPRF12(masterSecret, "key expansion", seed, 72)
	return keyBlockAES128CBCSHA{
		ClientMAC: block[0:20],
		ServerMAC: block[20:40],
		ClientKey: block[40:56],
		ServerKey: block[56:72],
	}
}

// finishedVerifyData computes the 12-byte verify_data for a TLS 1.2 client
// Finished. Per RFC 5246 §7.4.9:
//   verify_data = PRF(master_secret, "client finished",
//                     SHA-256(handshake_messages))[0:12]
func finishedVerifyData(masterSecret, transcriptHash []byte) []byte {
	return tlsPRF12(masterSecret, "client finished", transcriptHash, 12)
}

// encryptRecordAES128CBCSHA wraps a plaintext handshake message into the
// fully MAC-then-encrypted form a TLS 1.2 receiver expects. Returns the
// record-body bytes (explicit IV || ciphertext). The caller prepends the
// 5-byte record header (type, version, length).
//
// MAC input (RFC 5246 §6.2.3.1):
//   seq_num(8) || type(1) || version(2) || length(2) || plaintext
func encryptRecordAES128CBCSHA(plaintext []byte, keys keyBlockAES128CBCSHA, recordType byte, version uint16, seqNum uint64, iv []byte) ([]byte, error) {
	// Compute MAC over the canonical seq+type+version+length+plaintext stream.
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[0:8], seqNum)
	aad[8] = recordType
	binary.BigEndian.PutUint16(aad[9:11], version)
	binary.BigEndian.PutUint16(aad[11:13], uint16(len(plaintext)))

	mac := hmac.New(sha1.New, keys.ClientMAC)
	mac.Write(aad[:])
	mac.Write(plaintext)
	macSum := mac.Sum(nil)

	// Plaintext || MAC, then PKCS#7-style padding to AES block size (16).
	body := make([]byte, 0, len(plaintext)+len(macSum)+16)
	body = append(body, plaintext...)
	body = append(body, macSum...)
	padLen := 16 - (len(body) % 16)
	for i := 0; i < padLen; i++ {
		body = append(body, byte(padLen-1))
	}

	block, err := aes.NewCipher(keys.ClientKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(body))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, body)

	out := make([]byte, 0, len(iv)+len(ciphertext))
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out, nil
}
