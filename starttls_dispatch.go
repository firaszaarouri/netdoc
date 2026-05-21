package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Generic STARTTLS upgrade dispatcher — closes the biggest single gap to
// testssl.sh by adding TLS-upgrade handlers for the 14 protocols
// testssl.sh's `--starttls <protocol>` flag covers:
//
//   ftp / smtp / pop3 / imap / xmpp / xmpp-server / sieve / telnet /
//   ldap / irc / lmtp / nntp / postgres / mysql
//
// Each protocol speaks its own plaintext negotiation before the TLS
// handshake. The handlers here perform that negotiation, validate the
// server's acceptance, and return a net.Conn ready for tls.Client
// wrapping. The caller (checkTLS via --starttls) then performs the
// regular TLS handshake and the full posture pipeline (cert chain,
// version, ciphers, ALPN, fingerprints) runs unchanged.
//
// Wire-format references:
//   - SMTP STARTTLS: RFC 3207
//   - LMTP: RFC 2033 (LHLO instead of EHLO)
//   - POP3 STARTTLS: RFC 2595
//   - IMAP STARTTLS: RFC 2595 + RFC 3501
//   - FTP AUTH TLS: RFC 4217
//   - NNTP STARTTLS: RFC 4642
//   - XMPP STARTTLS: RFC 6120 §5
//   - Sieve STARTTLS: RFC 5804
//   - Telnet START_TLS: RFC 2946
//   - LDAP StartTLS: RFC 4511 + OID 1.3.6.1.4.1.1466.20037
//   - IRCv3 STARTTLS: ircv3.net/specs/extensions/tls-3.1
//   - MySQL TLS: dev.mysql.com/doc/internals/en/connection-phase-packets.html
//   - PostgreSQL TLS: postgresql.org/docs/current/protocol-flow.html §53.2.10

// startTLSProtocol is one of the canonical names testssl.sh accepts.
type startTLSProtocol string

const (
	starttlsSMTP       startTLSProtocol = "smtp"
	starttlsLMTP       startTLSProtocol = "lmtp"
	starttlsPOP3       startTLSProtocol = "pop3"
	starttlsIMAP       startTLSProtocol = "imap"
	starttlsFTP        startTLSProtocol = "ftp"
	starttlsNNTP       startTLSProtocol = "nntp"
	starttlsXMPP       startTLSProtocol = "xmpp"
	starttlsXMPPServer startTLSProtocol = "xmpp-server"
	starttlsSieve      startTLSProtocol = "sieve"
	starttlsTelnet     startTLSProtocol = "telnet"
	starttlsLDAP       startTLSProtocol = "ldap"
	starttlsIRC        startTLSProtocol = "irc"
	starttlsMySQL      startTLSProtocol = "mysql"
	starttlsPostgres   startTLSProtocol = "postgres"
)

// validSTARTTLSProtocols is the canonical list used for --starttls
// argument validation and --help-flags enumeration. Matches the
// testssl.sh names exactly so users can transfer muscle memory.
var validSTARTTLSProtocols = []startTLSProtocol{
	starttlsSMTP, starttlsLMTP, starttlsPOP3, starttlsIMAP, starttlsFTP,
	starttlsNNTP, starttlsXMPP, starttlsXMPPServer, starttlsSieve,
	starttlsTelnet, starttlsLDAP, starttlsIRC, starttlsMySQL,
	starttlsPostgres,
}

// parseSTARTTLSProtocol normalizes user input and returns the canonical
// constant. Tolerates a few common aliases (smtps → smtp because the
// upgrade is identical; imaps → imap; etc.) but does NOT accept
// implicit-TLS port ports.
func parseSTARTTLSProtocol(name string) (startTLSProtocol, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "smtp", "submission", "smtps":
		return starttlsSMTP, nil
	case "lmtp":
		return starttlsLMTP, nil
	case "pop3", "pop":
		return starttlsPOP3, nil
	case "imap":
		return starttlsIMAP, nil
	case "ftp":
		return starttlsFTP, nil
	case "nntp":
		return starttlsNNTP, nil
	case "xmpp":
		return starttlsXMPP, nil
	case "xmpp-server", "xmpps", "xmpp-s2s":
		return starttlsXMPPServer, nil
	case "sieve":
		return starttlsSieve, nil
	case "telnet":
		return starttlsTelnet, nil
	case "ldap":
		return starttlsLDAP, nil
	case "irc":
		return starttlsIRC, nil
	case "mysql":
		return starttlsMySQL, nil
	case "postgres", "postgresql", "pgsql":
		return starttlsPostgres, nil
	}
	return "", fmt.Errorf("unknown --starttls protocol %q (valid: smtp, lmtp, pop3, imap, ftp, nntp, xmpp, xmpp-server, sieve, telnet, ldap, irc, mysql, postgres)", name)
}

// defaultPortForSTARTTLS returns the canonical port a protocol listens on
// when --starttls is set without an explicit port.
func defaultPortForSTARTTLS(p startTLSProtocol) int {
	switch p {
	case starttlsSMTP:
		return 25
	case starttlsLMTP:
		return 24
	case starttlsPOP3:
		return 110
	case starttlsIMAP:
		return 143
	case starttlsFTP:
		return 21
	case starttlsNNTP:
		return 119
	case starttlsXMPP:
		return 5222
	case starttlsXMPPServer:
		return 5269
	case starttlsSieve:
		return 4190
	case starttlsTelnet:
		return 23
	case starttlsLDAP:
		return 389
	case starttlsIRC:
		return 6667
	case starttlsMySQL:
		return 3306
	case starttlsPostgres:
		return 5432
	}
	return 0
}

// upgradeToTLS performs the protocol-specific STARTTLS dance on a
// connected plaintext socket, returning either the original conn ready
// for tls.Client wrapping, or an error explaining where in the
// negotiation things went wrong. host is passed through to handlers
// that need it for protocol-level identification (XMPP `to=`, LDAP, etc).
func upgradeToTLS(conn net.Conn, host string, proto startTLSProtocol, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	switch proto {
	case starttlsSMTP:
		return starttlsSMTPHandshake(conn, "EHLO")
	case starttlsLMTP:
		return starttlsSMTPHandshake(conn, "LHLO")
	case starttlsPOP3:
		return starttlsPOP3Handshake(conn)
	case starttlsIMAP:
		return starttlsIMAPHandshake(conn)
	case starttlsFTP:
		return starttlsFTPHandshake(conn)
	case starttlsNNTP:
		return starttlsNNTPHandshake(conn)
	case starttlsXMPP:
		return starttlsXMPPHandshake(conn, host, false)
	case starttlsXMPPServer:
		return starttlsXMPPHandshake(conn, host, true)
	case starttlsSieve:
		return starttlsSieveHandshake(conn)
	case starttlsTelnet:
		return starttlsTelnetHandshake(conn)
	case starttlsLDAP:
		return starttlsLDAPHandshake(conn)
	case starttlsIRC:
		return starttlsIRCHandshake(conn)
	case starttlsMySQL:
		return starttlsMySQLHandshake(conn)
	case starttlsPostgres:
		return starttlsPostgresHandshake(conn)
	}
	return fmt.Errorf("upgradeToTLS: unsupported protocol %q", proto)
}

// dialSTARTTLS opens a TCP connection to addr, performs the protocol-
// specific STARTTLS negotiation, then wraps in tls.Client with the
// given config. Returns a connected *tls.Conn ready for ConnectionState
// inspection or further posture probing.
//
// This is the single function that callers (checkTLS et al) use to get
// an upgraded TLS connection — they don't see the protocol-specific
// machinery.
func dialSTARTTLS(addr, host string, proto startTLSProtocol, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("starttls dial: %w", err)
	}
	if err := upgradeToTLS(conn, host, proto, timeout); err != nil {
		conn.Close()
		return nil, err
	}
	// Reset deadline post-upgrade for the TLS handshake.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("starttls TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// =============================================================================
// Per-protocol handshake implementations
// =============================================================================

// SMTP / LMTP — RFC 3207. helo is "EHLO" (SMTP) or "LHLO" (LMTP).
//
//	S: 220 banner
//	C: <HELO> netdoc
//	S: 250-host ... 250-PIPELINING ... 250 STARTTLS
//	C: STARTTLS
//	S: 220 ready
func starttlsSMTPHandshake(conn net.Conn, helo string) error {
	rd := bufio.NewReader(conn)
	if _, err := readSMTPLine(rd); err != nil {
		return fmt.Errorf("smtp banner: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "%s netdoc\r\n", helo); err != nil {
		return fmt.Errorf("smtp %s: %w", helo, err)
	}
	ehlo, err := readSMTPLine(rd)
	if err != nil {
		return fmt.Errorf("smtp %s reply: %w", helo, err)
	}
	if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
		return errors.New("smtp: STARTTLS not advertised in EHLO/LHLO response")
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("smtp STARTTLS: %w", err)
	}
	reply, err := readSMTPLine(rd)
	if err != nil {
		return fmt.Errorf("smtp STARTTLS reply: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(reply), "220") {
		return fmt.Errorf("smtp STARTTLS refused: %s", truncate(strings.TrimSpace(reply), 60))
	}
	return nil
}

// readSMTPLine reads a multi-line SMTP reply per RFC 5321 §4.2.
// Lines start with a 3-digit code + '-' (continuation) or ' ' (final).
func readSMTPLine(r *bufio.Reader) (string, error) {
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return out.String(), err
		}
		out.WriteString(line)
		if len(line) < 4 {
			return out.String(), nil
		}
		if line[3] == ' ' {
			return out.String(), nil
		}
	}
}

// POP3 — RFC 2595. STLS command instead of STARTTLS.
//
//	S: +OK banner
//	C: STLS
//	S: +OK Begin TLS negotiation
func starttlsPOP3Handshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	banner, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 banner: %w", err)
	}
	if !strings.HasPrefix(banner, "+OK") {
		return fmt.Errorf("pop3: bad banner %q", truncate(strings.TrimSpace(banner), 60))
	}
	if _, err := io.WriteString(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("pop3 STLS: %w", err)
	}
	reply, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 STLS reply: %w", err)
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fmt.Errorf("pop3 STLS refused: %s", truncate(strings.TrimSpace(reply), 60))
	}
	return nil
}

// IMAP — RFC 2595 + RFC 3501. Tag-based; we use "a001".
//
//	S: * OK banner
//	C: a001 STARTTLS
//	S: a001 OK Begin TLS negotiation
func starttlsIMAPHandshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	banner, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap banner: %w", err)
	}
	if !strings.HasPrefix(banner, "* OK") {
		return fmt.Errorf("imap: bad banner %q", truncate(strings.TrimSpace(banner), 60))
	}
	if _, err := io.WriteString(conn, "a001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("imap STARTTLS: %w", err)
	}
	// IMAP may emit untagged responses before the tagged final. Read until
	// we see our tag.
	for i := 0; i < 5; i++ {
		line, err := rd.ReadString('\n')
		if err != nil {
			return fmt.Errorf("imap STARTTLS reply: %w", err)
		}
		if strings.HasPrefix(line, "a001 ") {
			if !strings.HasPrefix(line, "a001 OK") {
				return fmt.Errorf("imap STARTTLS refused: %s", truncate(strings.TrimSpace(line), 60))
			}
			return nil
		}
	}
	return errors.New("imap STARTTLS: no tagged reply in 5 lines")
}

// FTP — RFC 4217 AUTH TLS.
//
//	S: 220 banner
//	C: AUTH TLS
//	S: 234 AUTH TLS ok
func starttlsFTPHandshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	banner, err := readSMTPLine(rd) // FTP reuses the multi-line 3-digit-code format
	if err != nil {
		return fmt.Errorf("ftp banner: %w", err)
	}
	_ = banner
	if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("ftp AUTH TLS: %w", err)
	}
	reply, err := readSMTPLine(rd)
	if err != nil {
		return fmt.Errorf("ftp AUTH TLS reply: %w", err)
	}
	code := strings.TrimSpace(reply)
	if !(strings.HasPrefix(code, "234") || strings.HasPrefix(code, "200")) {
		return fmt.Errorf("ftp AUTH TLS refused: %s", truncate(code, 60))
	}
	return nil
}

// NNTP — RFC 4642.
//
//	S: 200 banner
//	C: STARTTLS
//	S: 382 Continue with TLS negotiation
func starttlsNNTPHandshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	if _, err := rd.ReadString('\n'); err != nil {
		return fmt.Errorf("nntp banner: %w", err)
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("nntp STARTTLS: %w", err)
	}
	reply, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("nntp STARTTLS reply: %w", err)
	}
	if !strings.HasPrefix(reply, "382") {
		return fmt.Errorf("nntp STARTTLS refused: %s", truncate(strings.TrimSpace(reply), 60))
	}
	return nil
}

// XMPP — RFC 6120 §5. Open a stream, wait for stream:features with
// starttls offer, send <starttls/>, wait for <proceed/>.
// jabberNS = "jabber:client" for c2s (5222), "jabber:server" for s2s (5269).
func starttlsXMPPHandshake(conn net.Conn, host string, isServer bool) error {
	ns := "jabber:client"
	if isServer {
		ns = "jabber:server"
	}
	openStream := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		ns, host,
	)
	if _, err := io.WriteString(conn, openStream); err != nil {
		return fmt.Errorf("xmpp stream open: %w", err)
	}
	// Read until we see the closing </stream:features> tag or starttls offer.
	buf := make([]byte, 4096)
	var collected strings.Builder
	for i := 0; i < 16; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			collected.Write(buf[:n])
		}
		if err != nil {
			break
		}
		// Sufficient signal: see the starttls offer namespace.
		if strings.Contains(collected.String(), "urn:ietf:params:xml:ns:xmpp-tls") {
			break
		}
		if strings.Contains(collected.String(), "</stream:features>") {
			break
		}
	}
	if !strings.Contains(collected.String(), "urn:ietf:params:xml:ns:xmpp-tls") {
		return errors.New("xmpp: server didn't advertise starttls in stream features")
	}
	if _, err := io.WriteString(conn, `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`); err != nil {
		return fmt.Errorf("xmpp starttls send: %w", err)
	}
	// Wait for <proceed/>.
	collected.Reset()
	for i := 0; i < 8; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			collected.Write(buf[:n])
		}
		if strings.Contains(collected.String(), "<proceed") {
			return nil
		}
		if strings.Contains(collected.String(), "<failure") {
			return errors.New("xmpp starttls: server replied <failure/>")
		}
		if err != nil {
			break
		}
	}
	return errors.New("xmpp starttls: no <proceed/> received")
}

// Sieve — RFC 5804. CRLF-line based, OK/NO/BYE responses.
//
//	S: "IMPLEMENTATION" ... "STARTTLS" ... OK
//	C: STARTTLS
//	S: OK
func starttlsSieveHandshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	// Read greeting until OK / NO / BYE line.
	var greet strings.Builder
	for i := 0; i < 32; i++ {
		line, err := rd.ReadString('\n')
		if err != nil {
			return fmt.Errorf("sieve banner: %w", err)
		}
		greet.WriteString(line)
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "OK") || strings.HasPrefix(t, "NO") || strings.HasPrefix(t, "BYE") {
			break
		}
	}
	if !strings.Contains(strings.ToUpper(greet.String()), `"STARTTLS"`) {
		return errors.New("sieve: STARTTLS capability not advertised")
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("sieve STARTTLS: %w", err)
	}
	reply, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("sieve STARTTLS reply: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(reply), "OK") {
		return fmt.Errorf("sieve STARTTLS refused: %s", truncate(strings.TrimSpace(reply), 60))
	}
	return nil
}

// Telnet START_TLS — RFC 2946. Uses IAC option negotiation.
//
//	C: IAC WILL START_TLS                       (FF FB 2E)
//	S: IAC DO START_TLS                         (FF FD 2E)
//	C: IAC SB START_TLS FOLLOWS IAC SE          (FF FA 2E 01 FF F0)
//	S: IAC SB START_TLS FOLLOWS IAC SE          (FF FA 2E 01 FF F0)
//	then upgrade.
//
// Telnet servers are rare in 2026 but the wire format is small and
// covers a documented testssl.sh protocol.
const telnetOptStartTLS = 0x2e

func starttlsTelnetHandshake(conn net.Conn) error {
	// IAC WILL START_TLS
	if _, err := conn.Write([]byte{0xff, 0xfb, telnetOptStartTLS}); err != nil {
		return fmt.Errorf("telnet WILL START_TLS: %w", err)
	}
	buf := make([]byte, 64)
	// Read until we see IAC DO START_TLS.
	got := false
	for i := 0; i < 16; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("telnet read: %w", err)
		}
		for j := 0; j+2 < n; j++ {
			if buf[j] == 0xff && buf[j+1] == 0xfd && buf[j+2] == telnetOptStartTLS {
				got = true
				break
			}
		}
		if got {
			break
		}
	}
	if !got {
		return errors.New("telnet: server didn't ack START_TLS option")
	}
	// IAC SB START_TLS FOLLOWS IAC SE
	if _, err := conn.Write([]byte{0xff, 0xfa, telnetOptStartTLS, 0x01, 0xff, 0xf0}); err != nil {
		return fmt.Errorf("telnet SB: %w", err)
	}
	return nil
}

// LDAP StartTLS — RFC 4511 §4.14 + OID 1.3.6.1.4.1.1466.20037.
// Sends an ExtendedRequest BER-encoded:
//
//	30 1d                          SEQUENCE length 29
//	   02 01 01                    INTEGER messageID = 1
//	   77 18                       [APPLICATION 23] ExtendedRequest length 24
//	      80 16                    [0] requestName OctetString length 22
//	         "1.3.6.1.4.1.1466.20037"
//
// Expects an ExtendedResponse with resultCode = 0 (success).
func starttlsLDAPHandshake(conn net.Conn) error {
	startTLSOID := "1.3.6.1.4.1.1466.20037"
	// Build BER manually.
	req := []byte{
		0x30, 0x1d, // SEQUENCE len 29
		0x02, 0x01, 0x01, // INTEGER messageID=1
		0x77, 0x18, // [APPLICATION 23] ExtendedRequest len 24
		0x80, byte(len(startTLSOID)), // [0] requestName OctetString
	}
	req = append(req, []byte(startTLSOID)...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("ldap StartTLS write: %w", err)
	}
	// Read response — at minimum a SEQUENCE wrapping the ExtendedResponse
	// with resultCode in the LDAPResult sub-structure. We look for a
	// resultCode byte of 0x00 right after the LDAPResult enum tag.
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		return fmt.Errorf("ldap StartTLS read: %w", err)
	}
	if n < 10 {
		return errors.New("ldap: short StartTLS response")
	}
	// Walk forward looking for the LDAPResult resultCode enum.
	// LDAPResult begins with 0x0a 0x01 <code>. resultCode 0 = success.
	for i := 0; i+2 < n; i++ {
		if resp[i] == 0x0a && resp[i+1] == 0x01 {
			if resp[i+2] == 0x00 {
				return nil
			}
			return fmt.Errorf("ldap StartTLS refused with resultCode %d", resp[i+2])
		}
	}
	return errors.New("ldap: couldn't parse StartTLS resultCode")
}

// IRC STARTTLS — IRCv3 tls-3.1 extension.
//
//	C: CAP LS\r\n
//	S: :server CAP * LS :tls ...
//	C: STARTTLS\r\n
//	S: :server 670 ... :STARTTLS successful, proceed with TLS handshake
func starttlsIRCHandshake(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "CAP LS\r\nSTARTTLS\r\n"); err != nil {
		return fmt.Errorf("irc CAP LS / STARTTLS: %w", err)
	}
	// Read until 670 numeric reply or end-of-stream.
	for i := 0; i < 32; i++ {
		line, err := rd.ReadString('\n')
		if err != nil {
			return fmt.Errorf("irc STARTTLS read: %w", err)
		}
		if strings.Contains(line, " 670 ") {
			return nil
		}
		if strings.Contains(line, " 691 ") {
			return errors.New("irc STARTTLS failed (numeric 691)")
		}
	}
	return errors.New("irc STARTTLS: no 670 numeric received")
}

// MySQL — handshake then SSLRequest packet.
// Wire format (Connection Phase, dev.mysql.com):
//
//	Server greets with a Handshake packet whose capabilities word has
//	the CLIENT_SSL flag (bit 0x800) when TLS is supported.
//	Client responds with a 32-byte SSL request:
//	  3B packet length (LE)
//	  1B sequence number = 1
//	  4B capability_flags (must include CLIENT_SSL)
//	  4B max_packet_size
//	  1B character_set
//	  23B reserved zeros
//
// Server then proceeds directly into TLS — no app-level ack.
func starttlsMySQLHandshake(conn net.Conn) error {
	// Read greeting packet header (4 bytes): 3B length + 1B seqnum.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("mysql greeting header: %w", err)
	}
	pktLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if pktLen < 1 || pktLen > 16384 {
		return fmt.Errorf("mysql: implausible greeting length %d", pktLen)
	}
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fmt.Errorf("mysql greeting body: %w", err)
	}
	// Find capability_flags. Layout after the protocol version (1B):
	//   server version (null-terminated string)
	//   connection ID (4B)
	//   auth-plugin-data-part-1 (8B)
	//   filler (1B = 0)
	//   capability_flags_lower (2B little-endian)
	// We don't parse the whole packet — just check the cap flag bit.
	caps := uint16(0)
	if len(body) > 0 && body[0] != 0x0a {
		return fmt.Errorf("mysql: unsupported protocol version 0x%02x", body[0])
	}
	// Walk past the null-terminated server version string.
	i := 1
	for i < len(body) && body[i] != 0 {
		i++
	}
	i++ // skip the null
	// Skip 4B connection ID + 8B auth-plugin-data + 1B filler.
	i += 4 + 8 + 1
	if i+2 > len(body) {
		return errors.New("mysql: greeting truncated before capability flags")
	}
	caps = uint16(body[i]) | uint16(body[i+1])<<8
	const clientSSL = 0x0800
	if caps&clientSSL == 0 {
		return errors.New("mysql: server doesn't advertise CLIENT_SSL capability")
	}

	// Send SSLRequest packet (32 bytes payload + 4-byte header).
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], 0x0a8af68f) // protocol-41 + SSL + plugin-auth + secure-conn
	binary.LittleEndian.PutUint32(payload[4:8], 16777216)   // max_packet_size = 16 MiB
	payload[8] = 0x21                                       // utf8mb3_general_ci charset
	// payload[9:32] is reserved zero bytes — already zero.
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = 0
	pkt[2] = 0
	pkt[3] = 1 // sequence number 1 (server sent 0)
	copy(pkt[4:], payload)
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("mysql SSLRequest: %w", err)
	}
	return nil
}

// PostgreSQL — SSLRequest message (8 bytes total):
//
//	00 00 00 08    length = 8 (big-endian)
//	04 D2 16 2F    SSLRequest code 80877103
//
// Server responds with single byte:
//
//	'S' = SSL supported, proceed
//	'N' = SSL not supported
//	error message starting with 'E' = older server / config error
func starttlsPostgresHandshake(conn net.Conn) error {
	req := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("postgres SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("postgres SSLRequest reply: %w", err)
	}
	switch resp[0] {
	case 'S':
		return nil
	case 'N':
		return errors.New("postgres: server doesn't support TLS")
	case 'E':
		return errors.New("postgres: server returned error to SSLRequest")
	default:
		return fmt.Errorf("postgres: unexpected SSLRequest reply byte 0x%02x", resp[0])
	}
}
