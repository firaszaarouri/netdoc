package main

import (
	"encoding/binary"
	"errors"
)

// TLS 1.3 NewSessionTicket parsing (RFC 8446 §4.6.1).
//
//	struct {
//	    uint32 ticket_lifetime;
//	    uint32 ticket_age_add;
//	    opaque ticket_nonce<0..255>;
//	    opaque ticket<1..2^16-1>;
//	    Extension extensions<0..2^16-2>;
//	} NewSessionTicket;
//
// The extensions block carries the early_data extension (type 42) whose
// payload is a single uint32 max_early_data_size. Presence with size > 0
// is the canonical 0-RTT capability signal.

type tls13NewSessionTicket struct {
	lifetime     uint32
	ageAdd       uint32
	nonce        []byte
	ticket       []byte
	maxEarlyData uint32 // 0 if early_data extension absent
}

// parseNewSessionTicket parses one NST handshake body (NOT including the
// 4-byte handshake header).
func parseNewSessionTicket(body []byte) (*tls13NewSessionTicket, error) {
	if len(body) < 9 {
		return nil, errors.New("NST: too short")
	}
	out := &tls13NewSessionTicket{}
	off := 0
	out.lifetime = binary.BigEndian.Uint32(body[off:])
	off += 4
	out.ageAdd = binary.BigEndian.Uint32(body[off:])
	off += 4

	// ticket_nonce<0..255>
	if off+1 > len(body) {
		return nil, errors.New("NST: missing nonce length")
	}
	nonceLen := int(body[off])
	off++
	if off+nonceLen > len(body) {
		return nil, errors.New("NST: nonce overflow")
	}
	out.nonce = append([]byte(nil), body[off:off+nonceLen]...)
	off += nonceLen

	// ticket<1..2^16-1>
	if off+2 > len(body) {
		return nil, errors.New("NST: missing ticket length")
	}
	ticketLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+ticketLen > len(body) {
		return nil, errors.New("NST: ticket overflow")
	}
	out.ticket = append([]byte(nil), body[off:off+ticketLen]...)
	off += ticketLen

	// extensions<0..2^16-2>
	if off+2 > len(body) {
		// Some encodings of malformed NSTs omit the extensions block
		// entirely; treat as zero-length.
		return out, nil
	}
	extLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+extLen > len(body) {
		return nil, errors.New("NST: extensions overflow")
	}
	exts := body[off : off+extLen]

	// Walk extensions looking for early_data (type 42).
	eo := 0
	for eo+4 <= len(exts) {
		etype := binary.BigEndian.Uint16(exts[eo:])
		eo += 2
		elen := int(binary.BigEndian.Uint16(exts[eo:]))
		eo += 2
		if eo+elen > len(exts) {
			return nil, errors.New("NST: extension length overflow")
		}
		edata := exts[eo : eo+elen]
		eo += elen
		if etype == extEarlyData {
			// In NewSessionTicket, early_data extension payload is a
			// single uint32 max_early_data_size (RFC 8446 §4.2.10).
			if len(edata) >= 4 {
				out.maxEarlyData = binary.BigEndian.Uint32(edata[:4])
			}
		}
	}
	return out, nil
}
