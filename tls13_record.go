package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// TLS 1.3 record protection (RFC 8446 §5).
//
// Once the handshake key schedule produces traffic keys, ALL subsequent
// records (handshake messages encoded as TLSPlaintext.type=23 application
// data) are encrypted with AES-128-GCM per:
//
//	struct {
//	    ContentType opaque_type = application_data;  // = 23
//	    ProtocolVersion legacy_record_version = 0x0303;
//	    uint16 length;
//	    opaque encrypted_record[TLSCiphertext.length];
//	} TLSCiphertext;
//
//	struct {
//	    opaque content[TLSPlaintext.length];        // the inner plaintext
//	    ContentType type;                            // real type (22 handshake, 23 app, 21 alert)
//	    uint8 zeros[length_of_padding];              // we always send length 0
//	} TLSInnerPlaintext;
//
// AEAD:
//
//	additional_data = record_header (5 bytes: type|version|length)
//	nonce          = iv XOR sequence_number_be64_in_low_8_bytes
//	ciphertext     = AES-128-GCM-Encrypt(key, nonce, plaintext_with_inner_type, additional_data)
//
// Sequence numbers start at 0 and increment per record. On TLS_AES_128_GCM_
// SHA256 (the only suite we offer), key=16B, iv=12B, tag=16B.
//
// The recordProtector struct owns one direction's keys + sequence counter.
// Two instances per traffic phase (one client write, one server read).

// recordProtector handles AEAD encrypt/decrypt for one TLS 1.3 record
// stream direction. seq is 64-bit, starts at 0, increments per record.
type recordProtector struct {
	key  []byte
	iv   []byte
	aead cipher.AEAD
	seq  uint64
}

// newRecordProtector builds a protector from a traffic secret by deriving
// the key+iv via TLS 1.3 key_expansion (HKDF-Expand-Label with "key"/"iv").
func newRecordProtector(trafficSecret []byte) (*recordProtector, error) {
	key, iv := recordKeys(trafficSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &recordProtector{key: key, iv: iv, aead: aead}, nil
}

// computeNonce returns iv XOR (seq encoded big-endian in low 8 bytes).
// The first 4 bytes of iv pass through; the last 8 are XORed with seq.
// RFC 8446 §5.3.
func (r *recordProtector) computeNonce() []byte {
	nonce := make([]byte, 12)
	copy(nonce, r.iv)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^r.seq)
	return nonce
}

// open decrypts one TLS 1.3 ciphertext record and returns
// (plaintext, innerType). The caller passes the full record including the
// 5-byte header — additional_data is exactly those 5 bytes per RFC 8446 §5.2.
//
// TLSInnerPlaintext appends the real ContentType to the plaintext and may
// add zero padding; we strip those after decryption.
func (r *recordProtector) open(record []byte) (plaintext []byte, innerType byte, err error) {
	if len(record) < 5 {
		return nil, 0, errors.New("tls13 record: too short for header")
	}
	headerType := record[0]
	if headerType != recordApplicationData {
		return nil, 0, errors.New("tls13 record: outer type not application_data")
	}
	cipherLen := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+cipherLen != len(record) {
		return nil, 0, errors.New("tls13 record: cipher length mismatch")
	}
	if cipherLen < r.aead.Overhead() {
		return nil, 0, errors.New("tls13 record: ciphertext shorter than AEAD tag")
	}

	nonce := r.computeNonce()
	aad := record[:5]
	pt, err := r.aead.Open(nil, nonce, record[5:], aad)
	if err != nil {
		return nil, 0, err
	}
	r.seq++

	// TLSInnerPlaintext: content || type(1) || zero_padding(N)
	// Walk backward from the end skipping zero padding to find the real type.
	for i := len(pt) - 1; i >= 0; i-- {
		if pt[i] != 0 {
			return pt[:i], pt[i], nil
		}
	}
	return nil, 0, errors.New("tls13 record: empty inner plaintext")
}

// seal encrypts one TLS 1.3 plaintext + innerType into the wire format,
// returning the full record (header + ciphertext). additional_data is
// the 5-byte record header per RFC 8446 §5.2.
func (r *recordProtector) seal(plaintext []byte, innerType byte) []byte {
	inner := make([]byte, 0, len(plaintext)+1)
	inner = append(inner, plaintext...)
	inner = append(inner, innerType)
	// We don't add padding — the server doesn't care about traffic-flow
	// observability for our probe.

	cipherLen := len(inner) + r.aead.Overhead()
	header := make([]byte, 5)
	header[0] = recordApplicationData
	header[1] = 0x03
	header[2] = 0x03
	binary.BigEndian.PutUint16(header[3:], uint16(cipherLen))

	nonce := r.computeNonce()
	out := make([]byte, 0, 5+cipherLen)
	out = append(out, header...)
	out = r.aead.Seal(out, nonce, inner, header)
	r.seq++
	return out
}
