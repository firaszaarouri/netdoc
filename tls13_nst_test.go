package main

import (
	"encoding/binary"
	"testing"
)

// Tests for the NewSessionTicket parser. Build canned NSTs covering:
// presence/absence of early_data, varied ticket sizes, malformed inputs.

// buildNST builds a minimal valid NewSessionTicket body (no handshake header).
func buildNST(maxEarlyData uint32, ticketLen, nonceLen int) []byte {
	out := make([]byte, 0, 32+ticketLen)
	out = binary.BigEndian.AppendUint32(out, 7200)        // lifetime
	out = binary.BigEndian.AppendUint32(out, 0xCAFEBABE)  // age_add
	// ticket_nonce<0..255>
	out = append(out, byte(nonceLen))
	for i := 0; i < nonceLen; i++ {
		out = append(out, byte(i))
	}
	// ticket<1..2^16-1>
	out = binary.BigEndian.AppendUint16(out, uint16(ticketLen))
	for i := 0; i < ticketLen; i++ {
		out = append(out, byte(i&0xff))
	}
	// extensions<0..2^16-2>
	if maxEarlyData == 0 {
		out = binary.BigEndian.AppendUint16(out, 0)
		return out
	}
	// early_data extension: type=42, length=4, value=max_early_data_size
	ext := make([]byte, 0, 8)
	ext = binary.BigEndian.AppendUint16(ext, 42) // early_data
	ext = binary.BigEndian.AppendUint16(ext, 4)
	ext = binary.BigEndian.AppendUint32(ext, maxEarlyData)
	out = binary.BigEndian.AppendUint16(out, uint16(len(ext)))
	out = append(out, ext...)
	return out
}

func TestParseNST_WithEarlyData(t *testing.T) {
	body := buildNST(14336, 64, 8) // Cloudflare's documented max
	nst, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nst.maxEarlyData != 14336 {
		t.Errorf("max_early_data: got %d want 14336", nst.maxEarlyData)
	}
	if len(nst.ticket) != 64 {
		t.Errorf("ticket length: got %d want 64", len(nst.ticket))
	}
	if len(nst.nonce) != 8 {
		t.Errorf("nonce length: got %d want 8", len(nst.nonce))
	}
	if nst.lifetime != 7200 {
		t.Errorf("lifetime: got %d want 7200", nst.lifetime)
	}
}

func TestParseNST_WithoutEarlyData(t *testing.T) {
	body := buildNST(0, 32, 0)
	nst, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nst.maxEarlyData != 0 {
		t.Errorf("max_early_data should be 0 when extension absent, got %d", nst.maxEarlyData)
	}
}

func TestParseNST_FacebookUnlimited(t *testing.T) {
	// Facebook returns UINT32_MAX = "unlimited".
	body := buildNST(0xFFFFFFFF, 16, 4)
	nst, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nst.maxEarlyData != 0xFFFFFFFF {
		t.Errorf("max_early_data UINT32_MAX: got %d", nst.maxEarlyData)
	}
}

func TestParseNST_TooShort(t *testing.T) {
	_, err := parseNewSessionTicket([]byte{1, 2, 3})
	if err == nil {
		t.Errorf("expected error for too-short NST")
	}
}

func TestParseNST_TicketOverflow(t *testing.T) {
	// Construct a body where ticket length exceeds remaining bytes.
	body := make([]byte, 0, 32)
	body = binary.BigEndian.AppendUint32(body, 100)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, 0) // nonce_len = 0
	body = binary.BigEndian.AppendUint16(body, 1000) // ticket claims 1000 bytes
	body = append(body, 0x42) // only 1 byte present
	_, err := parseNewSessionTicket(body)
	if err == nil {
		t.Errorf("expected error for ticket-length overflow")
	}
}

func TestParseNST_MissingExtensionsTolerated(t *testing.T) {
	// Some malformed NSTs omit the extensions block entirely after ticket.
	// Parser tolerates this and returns the NST with maxEarlyData=0.
	body := make([]byte, 0, 32)
	body = binary.BigEndian.AppendUint32(body, 100)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, 0) // empty nonce
	body = binary.BigEndian.AppendUint16(body, 4)
	body = append(body, 0xde, 0xad, 0xbe, 0xef) // ticket
	// No extensions trailer.
	nst, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("missing extensions block should be tolerated: %v", err)
	}
	if nst.maxEarlyData != 0 {
		t.Errorf("max_early_data should be 0, got %d", nst.maxEarlyData)
	}
}
