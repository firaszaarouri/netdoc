package main

import (
	"net"
	"strings"
	"time"
)

// Telnet (RFC 854) service probe. Telnet greets with IAC (0xFF)
// option-negotiation bytes followed by an ASCII banner. The probe:
//
//   1. TCP-connect to the target.
//   2. Read up to 4 KB or until 500 ms idle.
//   3. Strip IAC sequences — each IAC is 3 bytes (0xFF + verb + opt).
//   4. Return the surviving ASCII as the banner.
//
// Legacy infrastructure (industrial controllers, old switches, IP KVMs)
// still serves Telnet — fingerprinting it is genuinely useful for
// inventory. Modern services like SSH have replaced Telnet, so any
// hit on port 23 is itself a posture concern.

func probeTelnet(addr, _ string, timeout time.Duration) serviceInfo {
	var empty serviceInfo
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return empty
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Some Telnet servers wait for our DO/DONT/WILL/WONT bytes before
	// emitting the banner. Send a generic "WONT echo" (FF FC 01) so the
	// session advances. Best-effort; ignore errors.
	_, _ = conn.Write([]byte{0xff, 0xfc, 0x01})

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return empty
	}
	clean := stripTelnetIAC(buf[:n])
	if clean == "" {
		return empty
	}
	info := serviceInfo{
		Product: "Telnet",
		Banner:  clean,
		Extra:   map[string]string{"banner_raw_bytes": itoa(n)},
	}
	// Detect common Telnet daemon families from the banner text.
	low := strings.ToLower(clean)
	switch {
	case strings.Contains(low, "cisco"):
		info.Product = "Cisco IOS Telnet"
	case strings.Contains(low, "mikrotik") || strings.Contains(low, "routeros"):
		info.Product = "MikroTik RouterOS Telnet"
	case strings.Contains(low, "ubuntu") || strings.Contains(low, "debian") || strings.Contains(low, "linux"):
		info.Product = "Linux Telnet"
	case strings.Contains(low, "vxworks"):
		info.Product = "VxWorks Telnet"
	}
	return info
}

// stripTelnetIAC removes IAC option-negotiation sequences from b. Each
// IAC is `0xFF VERB OPT` (3 bytes) for VERB ∈ {WILL, WONT, DO, DONT}
// (0xFB..0xFE). 0xFF 0xFF is an escaped literal 0xFF. Other 0xFF cmds
// (SB=0xFA / SE=0xF0 sub-negotiation) are stripped greedily until SE
// or end of buffer. Returns the surviving printable ASCII, trimmed of
// leading/trailing whitespace, with internal newlines collapsed.
func stripTelnetIAC(b []byte) string {
	var out []byte
	i := 0
	for i < len(b) {
		c := b[i]
		if c != 0xff {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		next := b[i+1]
		switch {
		case next == 0xff:
			out = append(out, 0xff)
			i += 2
		case next >= 0xfb && next <= 0xfe:
			// WILL/WONT/DO/DONT — 3-byte sequence.
			i += 3
		case next == 0xfa:
			// SB subnegotiation — skip until IAC SE (0xff 0xf0).
			i += 2
			for i+1 < len(b) && !(b[i] == 0xff && b[i+1] == 0xf0) {
				i++
			}
			i += 2
		default:
			// Other IAC commands are 2 bytes.
			i += 2
		}
	}
	// Filter non-printables EXCEPT newline/tab, then trim.
	clean := make([]byte, 0, len(out))
	for _, c := range out {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7e) {
			clean = append(clean, c)
		}
	}
	return strings.TrimSpace(strings.ReplaceAll(string(clean), "\r\n", "\n"))
}
