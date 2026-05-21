package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// STARTTLS Command Injection probe. Mirrors testssl.sh's `--SI /
// --starttls-injection` flag.
//
// Vulnerability class: when a server doesn't drain or invalidate its
// read buffer between the plaintext STARTTLS command and the TLS
// handshake, an attacker MITMing the plaintext leg can pipeline
// arbitrary commands. After the legitimate client completes the
// handshake, those pipelined commands execute INSIDE the encrypted
// session — typically used to inject AUTH or DATA commands that the
// legitimate user appears to have sent.
//
// References:
//   CVE-2011-0411 — Postfix smtpd
//   CVE-2014-0207 — Cyrus IMAP
//   CVE-2011-1575 — Various IMAP/POP3
//   USENIX Sec 21 paper "Why TLS is better without STARTTLS" (Damian Poddebniak et al.)
//
// Detection technique (the same testssl.sh uses):
//
//   For SMTP/IMAP/POP3/FTP/NNTP, send the upgrade command WITH AN EXTRA
//   COMMAND PIPELINED IN THE SAME TCP SEGMENT. Examples:
//
//     SMTP:  "STARTTLS\r\nNOOP\r\n"
//     IMAP:  "a001 STARTTLS\r\na002 NOOP\r\n"
//     POP3:  "STLS\r\nNOOP\r\n"
//     FTP:   "AUTH TLS\r\nNOOP\r\n"
//     NNTP:  "STARTTLS\r\nHELP\r\n"
//
//   Then perform the TLS handshake, then read the FIRST response inside
//   the encrypted channel. A correctly-implemented server discards the
//   pipelined bytes after STARTTLS — the read returns the encrypted
//   service banner or times out cleanly. A VULNERABLE server processes
//   the pipelined command and the first encrypted read returns the
//   response to that command (e.g., "+OK NOOP completed" or "250 OK").
//
// This is one of the highest-impact missing testssl.sh probes for
// netdoc to ship — STARTTLS injection is still found in the wild on
// older Postfix/Sendmail/Cyrus deployments.

type starttlsInjectionResult struct {
	Probed     bool   `json:"probed"`
	Protocol   string `json:"protocol"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// probeSTARTTLSInjection runs the pipelined-command probe against a
// running STARTTLS-capable server. Returns Probed=false when the
// upgrade itself fails (not a vulnerability — just not in scope).
func probeSTARTTLSInjection(addr, host string, proto startTLSProtocol, timeout time.Duration) starttlsInjectionResult {
	out := starttlsInjectionResult{Protocol: string(proto)}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}

	// Look up the injection plan for this protocol. Not every protocol
	// in our STARTTLS dispatcher is supported here — we cover the four
	// where the injection class is well-documented + CVE-tracked.
	plan, ok := injectionPlans[proto]
	if !ok {
		out.Notes = "no injection probe defined for protocol " + string(proto)
		return out
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		out.Notes = "dial failed: " + tidyErr(err)
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Run the protocol greeting + capability negotiation up to the point
	// where STARTTLS would be issued.
	rd := bufio.NewReader(conn)
	if err := plan.preamble(conn, rd); err != nil {
		out.Notes = "preamble failed: " + tidyErr(err)
		return out
	}

	// Now send the injection — STARTTLS + a follow-up command in ONE
	// write. A non-vulnerable server treats only STARTTLS as in-band.
	if _, err := conn.Write([]byte(plan.injection)); err != nil {
		out.Notes = "injection write failed: " + tidyErr(err)
		return out
	}
	// Read the STARTTLS acknowledgment (the legitimate reply).
	ack, err := rd.ReadString('\n')
	if err != nil {
		out.Notes = "STARTTLS ack read failed: " + tidyErr(err)
		return out
	}
	if !plan.ackOK(ack) {
		out.Notes = "STARTTLS refused: " + truncate(strings.TrimSpace(ack), 60)
		return out
	}
	out.Probed = true

	// Perform the TLS handshake.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		out.Notes = "TLS handshake failed: " + tidyErr(err)
		return out
	}

	// Read one short response inside the encrypted channel with a quick
	// deadline. A non-vulnerable server returns its post-STARTTLS service
	// banner / capabilities; a VULNERABLE server returns the response to
	// the pipelined command.
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	encRD := bufio.NewReader(tlsConn)
	postLine, _ := encRD.ReadString('\n')
	if postLine == "" {
		out.Notes = "no encrypted response read within 2s — clean"
		return out
	}
	if plan.indicatesInjection(postLine) {
		out.Vulnerable = true
		out.Evidence = truncate(strings.TrimSpace(postLine), 100)
		out.Notes = "FIRST encrypted-channel response was the reply to the pipelined command — buffer not drained after STARTTLS"
	} else {
		out.Notes = "first encrypted response was service banner (not pipelined-command reply) — buffer correctly drained"
	}
	return out
}

// injectionPlan describes the pre-STARTTLS conversation, the actual
// pipelined-bytes payload, and the post-handshake response classifier
// for one protocol.
type injectionPlan struct {
	preamble         func(conn net.Conn, rd *bufio.Reader) error
	injection        string // bytes to send in one Write
	ackOK            func(line string) bool
	indicatesInjection func(encResponse string) bool
}

// injectionPlans covers the 4 protocols where STARTTLS Injection has
// CVE history. testssl.sh covers ftp/smtp/imap/pop3/lmtp; we ship those
// plus nntp.
var injectionPlans = map[startTLSProtocol]injectionPlan{
	starttlsSMTP: {
		preamble: func(conn net.Conn, rd *bufio.Reader) error {
			if _, err := rd.ReadString('\n'); err != nil {
				return fmt.Errorf("banner: %w", err)
			}
			if _, err := conn.Write([]byte("EHLO netdoc\r\n")); err != nil {
				return err
			}
			// Drain the multi-line EHLO reply.
			for i := 0; i < 32; i++ {
				line, err := rd.ReadString('\n')
				if err != nil {
					return err
				}
				if len(line) >= 4 && line[3] == ' ' {
					if !strings.Contains(strings.ToUpper(line), "STARTTLS") &&
						i == 0 {
						return errors.New("STARTTLS not in EHLO response")
					}
					return nil
				}
			}
			return errors.New("EHLO too many lines")
		},
		// Pipeline NOOP after STARTTLS. A vulnerable server returns
		// "250 2.0.0 OK" inside the encrypted channel.
		injection: "STARTTLS\r\nNOOP\r\n",
		ackOK: func(line string) bool {
			return strings.HasPrefix(strings.TrimSpace(line), "220")
		},
		indicatesInjection: func(s string) bool {
			t := strings.ToUpper(strings.TrimSpace(s))
			// A NOOP reply (250) inside the encrypted channel before any
			// legitimate prompt indicates the server processed our
			// plaintext-pipelined NOOP after the TLS upgrade.
			return strings.HasPrefix(t, "250") && strings.Contains(t, "OK")
		},
	},
	starttlsIMAP: {
		preamble: func(conn net.Conn, rd *bufio.Reader) error {
			banner, err := rd.ReadString('\n')
			if err != nil || !strings.HasPrefix(banner, "* OK") {
				return errors.New("bad IMAP banner")
			}
			return nil
		},
		injection: "a001 STARTTLS\r\na002 NOOP\r\n",
		ackOK: func(line string) bool {
			return strings.HasPrefix(line, "a001 OK")
		},
		indicatesInjection: func(s string) bool {
			// A "a002 OK NOOP" tag reply BEFORE the legitimate post-TLS
			// service banner indicates injection.
			return strings.HasPrefix(strings.TrimSpace(s), "a002")
		},
	},
	starttlsPOP3: {
		preamble: func(conn net.Conn, rd *bufio.Reader) error {
			banner, err := rd.ReadString('\n')
			if err != nil || !strings.HasPrefix(banner, "+OK") {
				return errors.New("bad POP3 banner")
			}
			return nil
		},
		injection: "STLS\r\nNOOP\r\n",
		ackOK: func(line string) bool {
			return strings.HasPrefix(line, "+OK")
		},
		indicatesInjection: func(s string) bool {
			// "+OK" appearing IMMEDIATELY after the TLS handshake is the
			// reply to our pipelined NOOP, not a legitimate prompt
			// (POP3 servers don't typically banner after STLS).
			return strings.HasPrefix(strings.TrimSpace(s), "+OK")
		},
	},
	starttlsFTP: {
		preamble: func(conn net.Conn, rd *bufio.Reader) error {
			// Drain greeting multi-line.
			for i := 0; i < 16; i++ {
				line, err := rd.ReadString('\n')
				if err != nil {
					return err
				}
				if len(line) >= 4 && line[3] == ' ' {
					return nil
				}
			}
			return errors.New("FTP greeting too long")
		},
		injection: "AUTH TLS\r\nNOOP\r\n",
		ackOK: func(line string) bool {
			t := strings.TrimSpace(line)
			return strings.HasPrefix(t, "234") || strings.HasPrefix(t, "200")
		},
		indicatesInjection: func(s string) bool {
			return strings.HasPrefix(strings.TrimSpace(s), "200")
		},
	},
	starttlsNNTP: {
		preamble: func(conn net.Conn, rd *bufio.Reader) error {
			_, err := rd.ReadString('\n')
			return err
		},
		injection: "STARTTLS\r\nHELP\r\n",
		ackOK: func(line string) bool {
			return strings.HasPrefix(line, "382")
		},
		indicatesInjection: func(s string) bool {
			return strings.HasPrefix(strings.TrimSpace(s), "100") // HELP success code
		},
	},
}

// starttlsInjectionHeadline returns a short summary string for the
// TLS check's secondary line.
func starttlsInjectionHeadline(r starttlsInjectionResult) string {
	if !r.Probed {
		return ""
	}
	if r.Vulnerable {
		return fmt.Sprintf("STARTTLS Injection VULNERABLE (%s) — pipelined command leaked into encrypted channel", r.Protocol)
	}
	return ""
}
