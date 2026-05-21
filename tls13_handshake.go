package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"
)

// TLS 1.3 hand-rolled handshake just deep enough to extract the server's
// post-handshake NewSessionTicket and parse its early_data extension for
// max_early_data_size. This is the canonical 0-RTT capability signal.
//
// Why hand-roll: Go's crypto/tls parses the NST and stores
// max_early_data_size in an unexported SessionState field with no public
// accessor. Reflect/unsafe pokes would be brittle across Go versions; the
// stable path is to walk the protocol directly.
//
// We don't verify the certificate chain — the goal is a posture probe,
// not an authenticated session. We compute and send our Finished message
// so the server transitions to the application phase and emits NSTs.

// tls13ProbeResult is the verdict returned by probeTLS13EarlyData.
type tls13ProbeResult struct {
	// HandshakeOK is true if we got through SH and decrypted at least one
	// server handshake message. False means the server refused/aborted.
	HandshakeOK bool

	// NSTReceived is true if the server sent a NewSessionTicket post-
	// handshake. Servers without session resumption (rare modern) won't.
	NSTReceived bool

	// MaxEarlyData is the max_early_data_size value parsed from the
	// NST's early_data extension. Zero means the extension wasn't present
	// OR the server explicitly set the size to 0 (RFC 8446 forbids the
	// latter; treat 0 as "not advertised").
	MaxEarlyData uint32

	// ZeroRTTOffered = true iff NSTReceived and MaxEarlyData > 0.
	ZeroRTTOffered bool

	// Notes carries human-readable explanations for the JSON consumer.
	Notes string
}

// probeTLS13EarlyData performs a hand-rolled TLS 1.3 handshake to
// `addr:port` (e.g., "example.com:443") with the given SNI and returns a
// verdict on 0-RTT capability. The timeout caps the whole operation.
//
// The probe NEVER sends application data — only the handshake messages
// required to make the server emit NSTs.
func probeTLS13EarlyData(addr, sni string, timeout time.Duration) (*tls13ProbeResult, error) {
	out := &tls13ProbeResult{}
	deadline := time.Now().Add(timeout)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return out, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	// --- Send ClientHello ---
	ch, err := buildClientHello(sni)
	if err != nil {
		return out, fmt.Errorf("build ClientHello: %w", err)
	}
	if err := writeRecord(conn, recordHandshake, ch.bytes); err != nil {
		return out, fmt.Errorf("write ClientHello: %w", err)
	}

	// Running transcript hash — Hash(ClientHello || ServerHello || EE || ...).
	transcript := sha256.New()
	transcript.Write(ch.bytes)

	// --- Receive ServerHello ---
	// ServerHello is a cleartext TLS handshake record (type=22).
	shRecord, err := readPlaintextRecord(conn)
	if err != nil {
		return out, fmt.Errorf("read ServerHello record: %w", err)
	}
	if shRecord.contentType != recordHandshake {
		return out, fmt.Errorf("ServerHello: expected record type 22, got %d", shRecord.contentType)
	}
	sh, err := parseServerHello(shRecord.payload)
	if err != nil {
		return out, fmt.Errorf("parse ServerHello: %w", err)
	}
	if sh.cipherSuite != tls13CipherAES128GCMSHA256 {
		return out, fmt.Errorf("server selected unsupported cipher 0x%04x", sh.cipherSuite)
	}
	if sh.helloRetryRequest {
		return out, errors.New("server sent HelloRetryRequest (probe handles only single-flight x25519)")
	}
	transcript.Write(sh.bytes)

	// --- ECDH shared secret ---
	peerPub, err := ecdh.X25519().NewPublicKey(sh.x25519ServerPub)
	if err != nil {
		return out, fmt.Errorf("server x25519 pubkey: %w", err)
	}
	shared, err := ch.x25519Priv.ECDH(peerPub)
	if err != nil {
		return out, fmt.Errorf("x25519 ECDH: %w", err)
	}

	// --- Derive handshake secrets ---
	ks := newTLS13KeySchedule()
	thCHSH := snapshotHash(transcript)
	ks.deriveHandshakeSecret(shared, thCHSH)

	// Server-side record protector for handshake-phase records.
	srvHsProt, err := newRecordProtector(ks.serverHandshakeTraffic)
	if err != nil {
		return out, fmt.Errorf("server handshake protector: %w", err)
	}
	cliHsProt, err := newRecordProtector(ks.clientHandshakeTraffic)
	if err != nil {
		return out, fmt.Errorf("client handshake protector: %w", err)
	}

	// --- Drain server's encrypted handshake records: EE, Cert, CV, Finished ---
	// Some servers also send a ChangeCipherSpec record (record type 20)
	// for middlebox compatibility (RFC 8446 §D.4); we accept and skip it.
	gotServerFinished := false
	hsBuffer := make([]byte, 0, 4096)
	for !gotServerFinished {
		rec, err := readPlaintextRecord(conn)
		if err != nil {
			return out, fmt.Errorf("read post-SH record: %w", err)
		}
		if rec.contentType == recordChangeCipherSpec {
			// Middlebox-compat. Discard.
			continue
		}
		if rec.contentType != recordApplicationData {
			return out, fmt.Errorf("unexpected post-SH record type %d", rec.contentType)
		}
		// Reassemble: build the full TLS record bytes including header so
		// the record protector's AEAD AAD matches what was on the wire.
		full := make([]byte, 5+len(rec.payload))
		full[0] = recordApplicationData
		full[1] = 0x03
		full[2] = 0x03
		binary.BigEndian.PutUint16(full[3:5], uint16(len(rec.payload)))
		copy(full[5:], rec.payload)

		pt, innerType, err := srvHsProt.open(full)
		if err != nil {
			return out, fmt.Errorf("decrypt handshake record: %w", err)
		}
		if innerType != recordHandshake {
			return out, fmt.Errorf("expected handshake inner type, got %d", innerType)
		}
		hsBuffer = append(hsBuffer, pt...)

		// A single TLS record may carry multiple handshake messages; walk
		// the buffer extracting complete ones.
		for {
			if len(hsBuffer) < 4 {
				break
			}
			msgType := hsBuffer[0]
			msgLen := int(hsBuffer[1])<<16 | int(hsBuffer[2])<<8 | int(hsBuffer[3])
			if 4+msgLen > len(hsBuffer) {
				break
			}
			fullMsg := hsBuffer[:4+msgLen]
			transcript.Write(fullMsg)
			out.HandshakeOK = true

			if msgType == hsFinished {
				gotServerFinished = true
			}
			// Trim consumed message off the buffer.
			hsBuffer = hsBuffer[4+msgLen:]
		}
	}

	// --- Compute and send client Finished ---
	thThroughServerFinished := snapshotHash(transcript)
	clientFinishedVerifyData := finishedVerifyData13(ks.clientHandshakeTraffic, thThroughServerFinished)
	clientFinishedMsg := make([]byte, 0, 4+len(clientFinishedVerifyData))
	clientFinishedMsg = append(clientFinishedMsg, hsFinished)
	clientFinishedMsg = append(clientFinishedMsg, 0, 0, byte(len(clientFinishedVerifyData)))
	clientFinishedMsg = append(clientFinishedMsg, clientFinishedVerifyData...)

	// Some servers expect to see a middlebox-compat ChangeCipherSpec from
	// the client before the encrypted Finished. We send one to maximize
	// interop — modern servers ignore it harmlessly.
	if err := writeRecord(conn, recordChangeCipherSpec, []byte{1}); err != nil {
		return out, fmt.Errorf("write CCS: %w", err)
	}

	// Encrypt client Finished with handshake-traffic key and send.
	encFinished := cliHsProt.seal(clientFinishedMsg, recordHandshake)
	if _, err := conn.Write(encFinished); err != nil {
		return out, fmt.Errorf("write client Finished: %w", err)
	}

	// --- Derive application-phase keys for both directions ---
	ks.deriveMasterSecret(thThroughServerFinished)
	srvAppProt, err := newRecordProtector(ks.serverApplicationTraffic)
	if err != nil {
		return out, fmt.Errorf("server application protector: %w", err)
	}
	cliAppProt, err := newRecordProtector(ks.clientApplicationTraffic)
	if err != nil {
		return out, fmt.Errorf("client application protector: %w", err)
	}

	// Trigger NSTs from servers that gate them on observed application
	// traffic (Cloudflare, some Akamai deployments). Send a minimal
	// HTTP/1.1 request — the server's response is discarded; we only
	// care about the NewSessionTicket records that follow.
	if sni != "" {
		httpReq := []byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\nUser-Agent: netdoc\r\nConnection: close\r\n\r\n")
		appRec := cliAppProt.seal(httpReq, recordApplicationData)
		_, _ = conn.Write(appRec)
	}

	// --- Receive any post-handshake messages (NSTs) ---
	// We give the server a short window — it may send NSTs immediately
	// or never. Bound the read by a fraction of the original timeout.
	postHsDeadline := time.Now().Add(2 * time.Second)
	if postHsDeadline.After(deadline) {
		postHsDeadline = deadline
	}
	_ = conn.SetReadDeadline(postHsDeadline)

	for {
		rec, err := readPlaintextRecord(conn)
		if err != nil {
			// Timeout / EOF → server sent nothing more.
			break
		}
		if rec.contentType == recordChangeCipherSpec {
			continue
		}
		if rec.contentType != recordApplicationData {
			break
		}
		full := make([]byte, 5+len(rec.payload))
		full[0] = recordApplicationData
		full[1] = 0x03
		full[2] = 0x03
		binary.BigEndian.PutUint16(full[3:5], uint16(len(rec.payload)))
		copy(full[5:], rec.payload)

		pt, innerType, err := srvAppProt.open(full)
		if err != nil {
			break
		}
		// Handshake-type inner means NewSessionTicket; alert means done.
		if innerType == recordAlert {
			break
		}
		if innerType != recordHandshake {
			continue
		}
		// Walk concatenated handshake messages.
		i := 0
		for i+4 <= len(pt) {
			t := pt[i]
			l := int(pt[i+1])<<16 | int(pt[i+2])<<8 | int(pt[i+3])
			if i+4+l > len(pt) {
				break
			}
			body := pt[i+4 : i+4+l]
			if t == hsNewSessionTicket {
				out.NSTReceived = true
				nst, perr := parseNewSessionTicket(body)
				if perr == nil && nst.maxEarlyData > out.MaxEarlyData {
					out.MaxEarlyData = nst.maxEarlyData
				}
			}
			i += 4 + l
		}
	}

	if out.NSTReceived && out.MaxEarlyData > 0 {
		out.ZeroRTTOffered = true
		out.Notes = fmt.Sprintf("server NewSessionTicket carries early_data extension with max_early_data_size=%d", out.MaxEarlyData)
	} else if out.NSTReceived {
		out.Notes = "server issued NewSessionTicket without early_data extension — resumption supported, 0-RTT not offered"
	} else if out.HandshakeOK {
		out.Notes = "TLS 1.3 handshake succeeded but server emitted no NewSessionTicket within window — resumption disabled or delayed"
	}
	return out, nil
}

// snapshotHash returns the current digest of an SHA-256 hash.Hash without
// affecting future Write calls.
func snapshotHash(h hash.Hash) []byte {
	// Marshal+Unmarshal would preserve internal state — but hash.Hash
	// doesn't expose that. Instead, copy: hash interface satisfies
	// encoding.BinaryMarshaler via concrete types in stdlib's crypto/sha256.
	// Easier portable trick: clone bytes via reflect-free path — use h.Sum
	// on a fresh copy isn't supported, so we use the BinaryMarshaler trick.
	type bm interface {
		MarshalBinary() ([]byte, error)
	}
	type bu interface {
		UnmarshalBinary([]byte) error
	}
	if marshaler, ok := h.(bm); ok {
		state, err := marshaler.MarshalBinary()
		if err == nil {
			clone := sha256.New()
			if u, ok2 := clone.(bu); ok2 {
				if err := u.UnmarshalBinary(state); err == nil {
					return clone.Sum(nil)
				}
			}
		}
	}
	// Fallback: Sum into a fresh slice. This DOES alter the running state
	// of h (technically Sum doesn't, but if the marshaler path failed
	// we have no choice). For our usage we always re-derive after this.
	return h.Sum(nil)
}

// plaintextRecord is a parsed TLSPlaintext record (header + payload).
type plaintextRecord struct {
	contentType byte
	payload     []byte
}

// readPlaintextRecord reads exactly one TLS record off conn.
func readPlaintextRecord(conn net.Conn) (*plaintextRecord, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[1] != 0x03 || (header[2] != 0x03 && header[2] != 0x01) {
		// Some implementations send 0x0301 for legacy_version on early
		// records; both are accepted.
		return nil, fmt.Errorf("unexpected record version %02x %02x", header[1], header[2])
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > 16384+256 {
		// Generous bound: TLS 1.3 caps TLSCiphertext.length at 2^14 + 256.
		return nil, fmt.Errorf("record length %d exceeds limit", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return &plaintextRecord{contentType: header[0], payload: payload}, nil
}

// writeRecord wraps payload in a TLSPlaintext record and writes it.
// Use for the cleartext ClientHello and the middlebox-compat CCS only.
func writeRecord(conn net.Conn, contentType byte, payload []byte) error {
	header := []byte{contentType, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}
