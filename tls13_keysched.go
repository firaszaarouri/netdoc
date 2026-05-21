package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// TLS 1.3 key schedule (RFC 8446 §7.1).
//
// The schedule chains three HKDF Extract+Expand stages:
//
//   early_secret      = HKDF-Extract(0, 0)                         // PSK = 0 since we don't do PSK
//   handshake_secret  = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)
//   master_secret     = HKDF-Extract(Derive-Secret(hs, "derived", ""), 0)
//
// Each stage yields traffic secrets via Derive-Secret(secret, label, transcript_hash):
//
//   client_handshake_traffic_secret = Derive-Secret(hs, "c hs traffic", H(CH..SH))
//   server_handshake_traffic_secret = Derive-Secret(hs, "s hs traffic", H(CH..SH))
//   client_application_traffic_secret_0 = Derive-Secret(ms, "c ap traffic", H(CH..server Finished))
//   server_application_traffic_secret_0 = Derive-Secret(ms, "s ap traffic", H(CH..server Finished))
//   resumption_master_secret = Derive-Secret(ms, "res master", H(CH..client Finished))
//
// Per-direction record-protection keys/IVs:
//
//   key  = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
//   iv   = HKDF-Expand-Label(traffic_secret, "iv",  "", iv_length)
//
// Finished verify_data:
//
//   finished_key = HKDF-Expand-Label(handshake_traffic_secret, "finished", "", Hash.length)
//   verify_data  = HMAC(finished_key, transcript_hash)
//
// All HKDF operations use SHA-256 here — we offer only TLS_AES_128_GCM_SHA256
// (cipher suite 0x1301). This keeps the implementation focused enough to be
// auditable while covering the mandatory-to-implement TLS 1.3 cipher.

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 §7.1:
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := make([]byte, 0, 4+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length))
	full := "tls13 " + label
	hkdfLabel = append(hkdfLabel, byte(len(full)))
	hkdfLabel = append(hkdfLabel, []byte(full)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, hkdfLabel)
	if _, err := r.Read(out); err != nil {
		// HKDF Expand is deterministic; an error here would indicate a
		// length > 255*hashLen request which we never make.
		return nil
	}
	return out
}

// deriveSecret applies RFC 8446 §7.1 Derive-Secret(Secret, Label, Messages):
//
//	HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
//
// where Hash is SHA-256 for our suite. `messages` is the transcript so far
// (the bytes of all handshake messages already exchanged).
func deriveSecret(secret []byte, label string, messages []byte) []byte {
	h := sha256.Sum256(messages)
	return hkdfExpandLabel(secret, label, h[:], sha256.Size)
}

// deriveSecretFromHash is a Derive-Secret variant that accepts a pre-computed
// transcript hash rather than the raw messages. Used after we've already
// rolled a SHA-256 running hash over the transcript to avoid re-hashing.
func deriveSecretFromHash(secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcriptHash, sha256.Size)
}

// hkdfExtract performs HKDF-Extract(salt, ikm) using SHA-256. When salt is
// nil it defaults to a 32-byte zero string (RFC 5869 §2.2).
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	if ikm == nil {
		ikm = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// tls13KeySchedule carries the full TLS 1.3 key-schedule state derived in
// order: early → handshake → master. Fields are populated as the
// transcript grows during the handshake walk.
type tls13KeySchedule struct {
	earlySecret             []byte // HKDF-Extract(0, 0)
	handshakeSecret         []byte // HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)
	masterSecret            []byte // HKDF-Extract(Derive-Secret(hs, "derived", ""), 0)
	clientHandshakeTraffic  []byte // Derive-Secret(hs, "c hs traffic", H(CH..SH))
	serverHandshakeTraffic  []byte // Derive-Secret(hs, "s hs traffic", H(CH..SH))
	clientApplicationTraffic []byte // Derive-Secret(ms, "c ap traffic", H(CH..server Finished))
	serverApplicationTraffic []byte // Derive-Secret(ms, "s ap traffic", H(CH..server Finished))
}

// newTLS13KeySchedule initializes the schedule with the early_secret stage.
// Subsequent stages are computed via deriveHandshakeSecret + deriveMasterSecret
// as the handshake progresses.
func newTLS13KeySchedule() *tls13KeySchedule {
	zero := make([]byte, sha256.Size)
	es := hkdfExtract(zero, zero) // HKDF-Extract(0, 0)
	return &tls13KeySchedule{earlySecret: es}
}

// deriveHandshakeSecret folds the ECDH shared secret into the schedule
// using HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE). Then
// derives the client/server handshake traffic secrets from the running
// transcript hash (H(ClientHello..ServerHello)).
func (s *tls13KeySchedule) deriveHandshakeSecret(ecdheShared, transcriptHashCHSH []byte) {
	derived := hkdfExpandLabel(s.earlySecret, "derived", emptyHashSHA256(), sha256.Size)
	s.handshakeSecret = hkdfExtract(derived, ecdheShared)
	s.clientHandshakeTraffic = deriveSecretFromHash(s.handshakeSecret, "c hs traffic", transcriptHashCHSH)
	s.serverHandshakeTraffic = deriveSecretFromHash(s.handshakeSecret, "s hs traffic", transcriptHashCHSH)
}

// deriveMasterSecret folds zero into the schedule using HKDF-Extract of
// Derive-Secret(hs, "derived", "") with the handshake_secret. Then derives
// client/server application traffic secrets from the transcript hash through
// server Finished.
func (s *tls13KeySchedule) deriveMasterSecret(transcriptHashThroughServerFinished []byte) {
	zero := make([]byte, sha256.Size)
	derived := hkdfExpandLabel(s.handshakeSecret, "derived", emptyHashSHA256(), sha256.Size)
	s.masterSecret = hkdfExtract(derived, zero)
	s.clientApplicationTraffic = deriveSecretFromHash(s.masterSecret, "c ap traffic", transcriptHashThroughServerFinished)
	s.serverApplicationTraffic = deriveSecretFromHash(s.masterSecret, "s ap traffic", transcriptHashThroughServerFinished)
}

// emptyHashSHA256 returns SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
// RFC 8446 §7.1 uses this whenever Derive-Secret takes an empty messages list.
func emptyHashSHA256() []byte {
	var h [sha256.Size]byte
	h2 := sha256.Sum256(nil)
	copy(h[:], h2[:])
	return h[:]
}

// finishedVerifyData13 computes the TLS 1.3 Finished verify_data:
//
//	finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
//	verify_data  = HMAC-SHA256(finished_key, transcript_hash)
//
// Suffix "13" disambiguates from the TLS 1.2 PRF-based helper in tls_crypto.go.
func finishedVerifyData13(trafficSecret, transcriptHash []byte) []byte {
	finishedKey := hkdfExpandLabel(trafficSecret, "finished", nil, sha256.Size)
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

// recordKeys derives the per-direction AES-128-GCM key+iv pair from a
// traffic secret. For TLS_AES_128_GCM_SHA256: key=16 bytes, iv=12 bytes.
func recordKeys(trafficSecret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(trafficSecret, "key", nil, 16)
	iv = hkdfExpandLabel(trafficSecret, "iv", nil, 12)
	return
}

// silenceUnused exists so future refactors don't strip the hash import
// if the only direct user (deriveSecret) is moved into a helper.
var _ hash.Hash = sha256.New()
