package main

import (
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"time"
)

// 0-RTT / early-data posture detection. Two-tier approach:
//
//  Tier 1 — HAND-ROLLED TLS 1.3 handshake: we drive the handshake
//  ourselves just deep enough to read the server's post-handshake
//  NewSessionTicket bytes and parse its early_data extension for the
//  authoritative max_early_data_size value. This is the bit-accurate
//  internet.nl-class signal: ZeroRTTOffered = true iff the server's NST
//  carries early_data with max_early_data_size > 0.
//
//  Tier 2 — PREREQUISITE probe via Go's stdlib crypto/tls. If the hand-
//  rolled probe fails (HelloRetryRequest required, server picks a cipher
//  we don't offer, network blip), fall back to detecting the three
//  prerequisites: TLS 1.3 supported + NST issued + ticket resumption
//  accepted. Still a strong posture signal, just not bit-exact.
//
// Result populated by probeZeroRTTPrereqs which orchestrates both tiers.

// zeroRTTResult records the posture verdict.
type zeroRTTResult struct {
	Probed          bool   `json:"probed"`
	TLS13Supported  bool   `json:"tls13_supported"`
	ResumptionWorks bool   `json:"resumption_works"`
	PrereqsMet      bool   `json:"prereqs_met"`             // tier-2 fallback verdict
	ZeroRTTOffered  bool   `json:"zero_rtt_offered,omitempty"` // tier-1 bit-accurate verdict (NST.early_data.max_early_data_size > 0)
	MaxEarlyData    uint32 `json:"max_early_data,omitempty"`   // tier-1 value when ZeroRTTOffered=true
	ProbeMode       string `json:"probe_mode,omitempty"`       // "tier1_handrolled" or "tier2_prereqs"
	Notes           string `json:"notes,omitempty"`
}

// probeZeroRTTPrereqs runs the two-tier 0-RTT detection. Tier 1 attempts
// the hand-rolled TLS 1.3 handshake for bit-accurate NST parsing; on
// any failure it falls through to the stdlib-based prerequisite probe.
func probeZeroRTTPrereqs(host string, port int, timeout time.Duration) zeroRTTResult {
	out := zeroRTTResult{Probed: true}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Tier 1 — hand-rolled probe. If it returns ZeroRTTOffered=true,
	// we have the authoritative answer and skip the stdlib path.
	// If HandshakeOK=true but NSTReceived=false, the server doesn't
	// emit NSTs (resumption disabled) — we know definitively, no need
	// for the tier-2 fallback.
	if r1, err := probeTLS13EarlyData(addr, host, timeout); err == nil && r1.HandshakeOK {
		out.ProbeMode = "tier1_handrolled"
		out.TLS13Supported = true
		out.ZeroRTTOffered = r1.ZeroRTTOffered
		out.MaxEarlyData = r1.MaxEarlyData
		out.ResumptionWorks = r1.NSTReceived
		out.PrereqsMet = r1.NSTReceived
		out.Notes = r1.Notes
		return out
	}

	// Tier 2 — stdlib prerequisite probe (existing behavior).
	out.ProbeMode = "tier2_prereqs"
	cache := tls.NewLRUClientSessionCache(2)
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: cache,
	}
	dialer := &net.Dialer{Timeout: timeout}

	// First handshake — establish session.
	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		// TLS 1.3 not supported.
		out.Notes = "TLS 1.3 handshake failed: " + tidyErr(err)
		return out
	}
	st1 := conn1.ConnectionState()
	out.TLS13Supported = st1.Version == tls.VersionTLS13
	// Drain post-handshake messages (NewSessionTicket) by writing a small
	// request + reading the response. This is the same trick the v1.11
	// session-resumption probe uses.
	_ = conn1.SetDeadline(time.Now().Add(timeout))
	_, _ = io.WriteString(conn1, "GET / HTTP/1.0\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	for {
		if _, err := conn1.Read(buf); err != nil {
			break
		}
	}
	conn1.Close()

	if !out.TLS13Supported {
		out.Notes = "server doesn't speak TLS 1.3"
		return out
	}
	// Second handshake — attempt resumption.
	conn2, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		out.Notes = "resumption handshake failed: " + tidyErr(err)
		return out
	}
	defer conn2.Close()
	st2 := conn2.ConnectionState()
	out.ResumptionWorks = st2.DidResume
	out.PrereqsMet = out.TLS13Supported && out.ResumptionWorks
	if out.PrereqsMet {
		out.Notes = "TLS 1.3 + ticket resumption — 0-RTT capable if server's NewSessionTicket advertises max_early_data_size"
	}
	return out
}

// zeroRTTHeadline returns a short summary for the TLS check line.
// Tier-1 verdicts get a definitive ✓ / ✗; tier-2 falls back to the
// prerequisite wording.
func zeroRTTHeadline(r zeroRTTResult) string {
	if !r.Probed {
		return ""
	}
	if r.ProbeMode == "tier1_handrolled" {
		if r.ZeroRTTOffered {
			return "0-RTT offered ✓"
		}
		if r.ResumptionWorks {
			return "0-RTT not offered (NST has no early_data)"
		}
		return ""
	}
	if r.PrereqsMet {
		return "0-RTT prereqs ✓"
	}
	return ""
}
