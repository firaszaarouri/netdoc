package main

import (
	"bytes"
	"testing"
)

// TestRecordProtector_Roundtrip — encrypt then decrypt restores the
// original plaintext + inner type, and the sequence counter advances
// such that the second record's nonce differs from the first.
func TestRecordProtector_Roundtrip(t *testing.T) {
	// Arbitrary 32-byte traffic secret (the keys are derived via HKDF).
	secret := hexDecode("0000000000000000000000000000000000000000000000000000000000000000")
	enc, err := newRecordProtector(secret)
	if err != nil {
		t.Fatalf("newRecordProtector: %v", err)
	}
	dec, err := newRecordProtector(secret)
	if err != nil {
		t.Fatalf("newRecordProtector: %v", err)
	}

	// First record.
	pt1 := []byte("hello tls 1.3 record")
	rec1 := enc.seal(pt1, recordHandshake)
	got1, innerType1, err := dec.open(rec1)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	if !bytes.Equal(got1, pt1) {
		t.Fatalf("plaintext mismatch:\ngot  %x\nwant %x", got1, pt1)
	}
	if innerType1 != recordHandshake {
		t.Fatalf("inner type #1: got %d want %d", innerType1, recordHandshake)
	}

	// Second record — sequence counter must have advanced. Same plaintext
	// should produce DIFFERENT ciphertext bytes.
	rec2 := enc.seal(pt1, recordHandshake)
	if bytes.Equal(rec1, rec2) {
		t.Fatalf("sequence counter not advancing — duplicate ciphertext on rec2")
	}
	got2, innerType2, err := dec.open(rec2)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	if !bytes.Equal(got2, pt1) {
		t.Fatalf("plaintext mismatch #2:\ngot  %x\nwant %x", got2, pt1)
	}
	if innerType2 != recordHandshake {
		t.Fatalf("inner type #2: got %d want %d", innerType2, recordHandshake)
	}

	// Third record with different inner type — confirms inner-type stripping.
	pt3 := []byte("app data here")
	rec3 := enc.seal(pt3, recordApplicationData)
	got3, innerType3, err := dec.open(rec3)
	if err != nil {
		t.Fatalf("open #3: %v", err)
	}
	if !bytes.Equal(got3, pt3) {
		t.Fatalf("plaintext mismatch #3:\ngot  %x\nwant %x", got3, pt3)
	}
	if innerType3 != recordApplicationData {
		t.Fatalf("inner type #3: got %d want %d", innerType3, recordApplicationData)
	}
}

// TestRecordProtector_NonceXOR — manually exercise the iv XOR seq
// computation to guard against off-by-one in the nonce construction.
func TestRecordProtector_NonceXOR(t *testing.T) {
	r := &recordProtector{
		iv: hexDecode("000102030405060708090a0b"),
	}
	// seq=0 → nonce = iv unchanged
	r.seq = 0
	want0 := hexDecode("000102030405060708090a0b")
	if got := r.computeNonce(); !bytes.Equal(got, want0) {
		t.Errorf("nonce seq=0: got %x want %x", got, want0)
	}
	// seq=1 → low byte XOR 1
	r.seq = 1
	want1 := hexDecode("000102030405060708090a0a")
	if got := r.computeNonce(); !bytes.Equal(got, want1) {
		t.Errorf("nonce seq=1: got %x want %x", got, want1)
	}
	// seq=0x100 → byte index 10 XOR 1
	r.seq = 0x100
	want256 := hexDecode("000102030405060708090b0b")
	if got := r.computeNonce(); !bytes.Equal(got, want256) {
		t.Errorf("nonce seq=0x100: got %x want %x", got, want256)
	}
}
