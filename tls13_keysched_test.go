package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TLS 1.3 key-schedule test vectors from RFC 8448 §3 (Simple 1-RTT Handshake).
// These pin our HKDF-Extract / HKDF-Expand-Label / Derive-Secret implementations
// against the IETF reference trace. Any divergence from RFC 8448's listed
// outputs would indicate a fundamental bug in the schedule and must be
// caught before higher layers (record decrypt, NST parse) get built on top.

func hexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestEmptyHashSHA256 — the well-known constant SHA-256("") used in TLS 1.3
// Derive-Secret when the messages parameter is empty (e.g., for the "derived"
// transition between key schedule stages).
func TestEmptyHashSHA256(t *testing.T) {
	want := hexDecode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if got := emptyHashSHA256(); !bytes.Equal(got, want) {
		t.Fatalf("SHA-256(\"\") mismatch: got %x want %x", got, want)
	}
}

// TestRFC8448_EarlySecret — early_secret = HKDF-Extract(0, 0) (RFC 8448 §3,
// "key schedule: early secret").
func TestRFC8448_EarlySecret(t *testing.T) {
	want := hexDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	zero := make([]byte, 32)
	got := hkdfExtract(zero, zero)
	if !bytes.Equal(got, want) {
		t.Fatalf("early_secret mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestRFC8448_DerivedFromEarly — HKDF-Expand-Label(early_secret, "derived",
// SHA-256(""), 32) — the secret that feeds into the next HKDF-Extract to
// produce handshake_secret (RFC 8448 §3, "key schedule: derived").
func TestRFC8448_DerivedFromEarly(t *testing.T) {
	earlySecret := hexDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	want := hexDecode("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
	got := hkdfExpandLabel(earlySecret, "derived", emptyHashSHA256(), 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("derived-from-early mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestRFC8448_HandshakeSecret — HKDF-Extract(derived_from_early, ECDHE).
// RFC 8448 §3 specifies the ECDHE shared secret and the resulting
// handshake_secret.
func TestRFC8448_HandshakeSecret(t *testing.T) {
	derivedFromEarly := hexDecode("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
	ecdhe := hexDecode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
	want := hexDecode("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	got := hkdfExtract(derivedFromEarly, ecdhe)
	if !bytes.Equal(got, want) {
		t.Fatalf("handshake_secret mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestRFC8448_ClientHandshakeTrafficSecret — Derive-Secret(handshake_secret,
// "c hs traffic", H(ClientHello..ServerHello)). RFC 8448 §3 provides both the
// transcript hash and the expected output.
func TestRFC8448_ClientHandshakeTrafficSecret(t *testing.T) {
	hsSecret := hexDecode("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	transcriptCHSH := hexDecode("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	want := hexDecode("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	got := deriveSecretFromHash(hsSecret, "c hs traffic", transcriptCHSH)
	if !bytes.Equal(got, want) {
		t.Fatalf("c hs traffic mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestRFC8448_ServerHandshakeTrafficSecret — same context, server side.
func TestRFC8448_ServerHandshakeTrafficSecret(t *testing.T) {
	hsSecret := hexDecode("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	transcriptCHSH := hexDecode("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	want := hexDecode("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	got := deriveSecretFromHash(hsSecret, "s hs traffic", transcriptCHSH)
	if !bytes.Equal(got, want) {
		t.Fatalf("s hs traffic mismatch:\ngot  %x\nwant %x", got, want)
	}
}

// TestRFC8448_ServerHandshakeKey — recordKeys() derives key+iv from a traffic
// secret. RFC 8448 §3 lists the server handshake write_key and write_iv
// derived from server_handshake_traffic_secret.
func TestRFC8448_ServerHandshakeKey(t *testing.T) {
	sHsTraffic := hexDecode("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	wantKey := hexDecode("3fce516009c21727d0f2e4e86ee403bc")
	wantIV := hexDecode("5d313eb2671276ee13000b30")
	key, iv := recordKeys(sHsTraffic)
	if !bytes.Equal(key, wantKey) {
		t.Errorf("server handshake key mismatch:\ngot  %x\nwant %x", key, wantKey)
	}
	if !bytes.Equal(iv, wantIV) {
		t.Errorf("server handshake iv mismatch:\ngot  %x\nwant %x", iv, wantIV)
	}
}

// TestNewTLS13KeySchedule_FullChain — runs the full schedule using
// newTLS13KeySchedule + deriveHandshakeSecret with RFC 8448 §3 inputs,
// confirming that the orchestrating struct produces identical outputs
// to the per-function tests above.
func TestNewTLS13KeySchedule_FullChain(t *testing.T) {
	ks := newTLS13KeySchedule()
	wantEarly := hexDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	if !bytes.Equal(ks.earlySecret, wantEarly) {
		t.Fatalf("earlySecret mismatch:\ngot  %x\nwant %x", ks.earlySecret, wantEarly)
	}

	ecdhe := hexDecode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
	transcriptCHSH := hexDecode("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	ks.deriveHandshakeSecret(ecdhe, transcriptCHSH)

	wantHS := hexDecode("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	if !bytes.Equal(ks.handshakeSecret, wantHS) {
		t.Errorf("handshakeSecret mismatch:\ngot  %x\nwant %x", ks.handshakeSecret, wantHS)
	}
	wantCHST := hexDecode("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	if !bytes.Equal(ks.clientHandshakeTraffic, wantCHST) {
		t.Errorf("clientHandshakeTraffic mismatch:\ngot  %x\nwant %x", ks.clientHandshakeTraffic, wantCHST)
	}
	wantSHST := hexDecode("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	if !bytes.Equal(ks.serverHandshakeTraffic, wantSHST) {
		t.Errorf("serverHandshakeTraffic mismatch:\ngot  %x\nwant %x", ks.serverHandshakeTraffic, wantSHST)
	}
}
