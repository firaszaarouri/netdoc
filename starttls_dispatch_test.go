package main

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// Tests for the STARTTLS dispatcher — closes the biggest testssl.sh
// coverage gap. Network-dependent paths are exercised via in-process
// pipe pairs so we can pin the exact wire bytes each protocol expects.

// --- Protocol-name resolution tests ---

func TestParseSTARTTLSProtocol_KnownNames(t *testing.T) {
	cases := map[string]startTLSProtocol{
		"smtp":          starttlsSMTP,
		"SMTP":          starttlsSMTP,
		"submission":    starttlsSMTP,
		"smtps":         starttlsSMTP, // alias maps to same handshake
		"lmtp":          starttlsLMTP,
		"pop3":          starttlsPOP3,
		"pop":           starttlsPOP3,
		"imap":          starttlsIMAP,
		"ftp":           starttlsFTP,
		"nntp":          starttlsNNTP,
		"xmpp":          starttlsXMPP,
		"xmpp-server":   starttlsXMPPServer,
		"sieve":         starttlsSieve,
		"telnet":        starttlsTelnet,
		"ldap":          starttlsLDAP,
		"irc":           starttlsIRC,
		"mysql":         starttlsMySQL,
		"postgres":      starttlsPostgres,
		"postgresql":    starttlsPostgres,
		"pgsql":         starttlsPostgres,
		"  imap  ":      starttlsIMAP, // whitespace tolerance
	}
	for in, want := range cases {
		got, err := parseSTARTTLSProtocol(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestParseSTARTTLSProtocol_Invalid(t *testing.T) {
	for _, bad := range []string{"", "https", "tls", "foobar", "smtp ssh"} {
		if _, err := parseSTARTTLSProtocol(bad); err == nil {
			t.Errorf("%q: expected error, got nil", bad)
		}
	}
}

func TestDefaultPortForSTARTTLS_AllProtocolsMapped(t *testing.T) {
	// Every constant in the canonical list must have a non-zero default
	// port, otherwise --starttls <p> with no explicit port targets 0.
	for _, p := range validSTARTTLSProtocols {
		if defaultPortForSTARTTLS(p) == 0 {
			t.Errorf("protocol %q has no default port", p)
		}
	}
}

func TestDefaultPortForSTARTTLS_KnownValues(t *testing.T) {
	cases := map[startTLSProtocol]int{
		starttlsSMTP:       25,
		starttlsLMTP:       24,
		starttlsPOP3:       110,
		starttlsIMAP:       143,
		starttlsFTP:        21,
		starttlsNNTP:       119,
		starttlsXMPP:       5222,
		starttlsXMPPServer: 5269,
		starttlsSieve:      4190,
		starttlsTelnet:     23,
		starttlsLDAP:       389,
		starttlsIRC:        6667,
		starttlsMySQL:      3306,
		starttlsPostgres:   5432,
	}
	for p, want := range cases {
		if got := defaultPortForSTARTTLS(p); got != want {
			t.Errorf("%q: got port %d want %d", p, got, want)
		}
	}
}

// --- readSMTPLine (multi-line reply) tests ---

func TestReadSMTPLine_SingleLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("220 mail.example.com ESMTP ready\r\n"))
	got, err := readSMTPLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "220 mail.example.com") {
		t.Errorf("got %q", got)
	}
}

func TestReadSMTPLine_MultiLine(t *testing.T) {
	multi := "250-mail.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250 STARTTLS\r\n"
	r := bufio.NewReader(strings.NewReader(multi))
	got, err := readSMTPLine(r)
	if err != nil {
		t.Fatal(err)
	}
	// All four lines should be captured into one string.
	if !strings.Contains(got, "STARTTLS") {
		t.Errorf("STARTTLS line missed in multi-line read: %q", got)
	}
	if strings.Count(got, "250") != 4 {
		t.Errorf("expected 4 instances of '250', got %d in %q", strings.Count(got, "250"), got)
	}
}

// --- Protocol-handler tests via in-process pipe ---
//
// Each test creates a net.Pipe pair, runs the dispatcher handshake on
// one end, and acts as the server on the other to verify the exact
// bytes our client sends.

// fakeServer is a goroutine running on the server side of net.Pipe. It
// expects a sequence of (recv-pattern, send-response) exchanges.
func fakeServer(t *testing.T, srv net.Conn, exchanges []struct {
	send   string
	expect string
}) {
	t.Helper()
	rd := bufio.NewReader(srv)
	for i, ex := range exchanges {
		if ex.send != "" {
			if _, err := srv.Write([]byte(ex.send)); err != nil {
				t.Errorf("exchange %d send: %v", i, err)
				return
			}
		}
		if ex.expect != "" {
			line, err := rd.ReadString('\n')
			if err != nil {
				t.Errorf("exchange %d read: %v", i, err)
				return
			}
			if !strings.Contains(line, ex.expect) {
				t.Errorf("exchange %d: got %q want substring %q", i, line, ex.expect)
				return
			}
		}
	}
	srv.Close()
}

func TestSTARTTLS_SMTP_Handshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan error, 1)
	go func() {
		done <- starttlsSMTPHandshake(cli, "EHLO")
	}()

	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "220 mail.example.com ESMTP ready\r\n"},
		{expect: "EHLO"},
		{send: "250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"},
		{expect: "STARTTLS"},
		{send: "220 Ready to start TLS\r\n"},
	})

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsSMTPHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("starttlsSMTPHandshake: timeout")
	}
}

func TestSTARTTLS_SMTP_NoSTARTTLSAdvertised(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan error, 1)
	go func() {
		done <- starttlsSMTPHandshake(cli, "EHLO")
	}()
	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "220 mail.example.com ESMTP\r\n"},
		{expect: "EHLO"},
		{send: "250-mail.example.com\r\n250 PIPELINING\r\n"}, // no STARTTLS
	})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "STARTTLS not advertised") {
			t.Errorf("expected 'STARTTLS not advertised' error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_POP3_STLSHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan error, 1)
	go func() { done <- starttlsPOP3Handshake(cli) }()

	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "+OK POP3 ready\r\n"},
		{expect: "STLS"},
		{send: "+OK Begin TLS negotiation\r\n"},
	})

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsPOP3Handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_POP3_BadBanner(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsPOP3Handshake(cli) }()
	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "-ERR not ready\r\n"},
	})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "bad banner") {
			t.Errorf("expected bad-banner error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_IMAP_Handshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	done := make(chan error, 1)
	go func() { done <- starttlsIMAPHandshake(cli) }()

	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "* OK IMAP4rev1 ready\r\n"},
		{expect: "a001 STARTTLS"},
		{send: "a001 OK Begin TLS negotiation\r\n"},
	})

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsIMAPHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_FTP_AuthTLS(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsFTPHandshake(cli) }()
	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "220 ProFTPD ready\r\n"},
		{expect: "AUTH TLS"},
		{send: "234 AUTH TLS successful\r\n"},
	})
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsFTPHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_NNTP_Handshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsNNTPHandshake(cli) }()
	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: "200 news.example.com ready\r\n"},
		{expect: "STARTTLS"},
		{send: "382 Continue with TLS negotiation\r\n"},
	})
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsNNTPHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_Postgres_AcceptByte(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsPostgresHandshake(cli) }()
	go func() {
		// Server reads the 8-byte SSLRequest, replies 'S'.
		buf := make([]byte, 8)
		if _, err := srv.Read(buf); err != nil {
			t.Errorf("postgres read SSLRequest: %v", err)
			return
		}
		// Verify the SSLRequest magic.
		expected := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
		for i, b := range expected {
			if buf[i] != b {
				t.Errorf("SSLRequest byte %d: got 0x%02x want 0x%02x", i, buf[i], b)
			}
		}
		srv.Write([]byte{'S'})
		srv.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsPostgresHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_Postgres_NSupport(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsPostgresHandshake(cli) }()
	go func() {
		buf := make([]byte, 8)
		srv.Read(buf)
		srv.Write([]byte{'N'}) // No SSL
		srv.Close()
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "doesn't support TLS") {
			t.Errorf("expected 'doesn't support TLS' error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_LDAP_Success(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsLDAPHandshake(cli) }()
	go func() {
		buf := make([]byte, 256)
		n, _ := srv.Read(buf)
		// Verify the BER-encoded StartTLS OID is present in the request.
		if n < 10 {
			t.Errorf("LDAP request too short: %d bytes", n)
		}
		if !strings.Contains(string(buf[:n]), "1.3.6.1.4.1.1466.20037") {
			t.Errorf("LDAP request didn't contain StartTLS OID")
		}
		// Send a minimal ExtendedResponse with resultCode=0 (success).
		// Layout: SEQUENCE { INTEGER msgID=1, ExtendedResponse { LDAPResult { ENUMERATED 0, ... } } }
		// Minimum-viable response: SEQUENCE wrapping resultCode enum 0.
		resp := []byte{
			0x30, 0x0c, // SEQUENCE len 12
			0x02, 0x01, 0x01, // INTEGER msgID=1
			0x78, 0x07, // [APPLICATION 24] ExtendedResponse len 7
			0x0a, 0x01, 0x00, // ENUMERATED resultCode=0 (success)
			0x04, 0x00, // OctetString matchedDN=""
			0x04, 0x00, // OctetString errorMessage=""
		}
		srv.Write(resp)
		srv.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsLDAPHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_LDAP_Refused(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsLDAPHandshake(cli) }()
	go func() {
		buf := make([]byte, 256)
		srv.Read(buf)
		// resultCode=53 (unwillingToPerform — common refusal).
		resp := []byte{
			0x30, 0x0c,
			0x02, 0x01, 0x01,
			0x78, 0x07,
			0x0a, 0x01, 0x35, // ENUMERATED 53
			0x04, 0x00,
			0x04, 0x00,
		}
		srv.Write(resp)
		srv.Close()
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "53") {
			t.Errorf("expected resultCode-53 error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSTARTTLS_Sieve_Handshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	done := make(chan error, 1)
	go func() { done <- starttlsSieveHandshake(cli) }()
	go fakeServer(t, srv, []struct {
		send   string
		expect string
	}{
		{send: `"IMPLEMENTATION" "ExampleSieve 1.0"` + "\r\n"},
		{send: `"STARTTLS"` + "\r\n"},
		{send: "OK\r\n"},
		{expect: "STARTTLS"},
		{send: "OK\r\n"},
	})
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("starttlsSieveHandshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
