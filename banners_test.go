package main

import "testing"

func TestParseBanner(t *testing.T) {
	cases := []struct {
		banner      string
		wantProduct string
		wantVersion string
	}{
		// SSH — three common implementations
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "OpenSSH", "8.9p1"},
		{"SSH-2.0-libssh_0.10.4", "libssh", "0.10.4"},
		{"SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"},

		// SMTP — Postfix and Exim both surface a daemon name
		{"220 mx.example.com ESMTP Postfix (Ubuntu)", "Postfix", ""},
		{"220 mx ESMTP Exim 4.94 Mon, 01 Jan 2020", "Exim", "4.94"},

		// FTP
		{"220 (vsFTPd 3.0.3)", "vsFTPd", "3.0.3"},
		{"220 ProFTPD 1.3.7 Server", "ProFTPD", "1.3.7"},

		// IMAP / POP3 — Dovecot version isn't usually on the wire
		{"* OK [CAPABILITY IMAP4REV1] Dovecot ready.", "Dovecot", ""},
		{"+OK Dovecot (Ubuntu) ready.", "Dovecot", ""},

		// VNC
		{"RFB 003.008", "VNC", "003.008"},

		// Cases that should NOT parse (no rule matches)
		{"", "", ""},
		{"random garbage", "", ""},
		{"SSH-2.0-8ad108e", "", ""}, // GitHub uses a commit-hash banner
	}
	for _, c := range cases {
		gotProduct, gotVersion := parseBanner(c.banner)
		if gotProduct != c.wantProduct || gotVersion != c.wantVersion {
			t.Errorf("parseBanner(%q) = (%q, %q); want (%q, %q)",
				c.banner, gotProduct, gotVersion, c.wantProduct, c.wantVersion)
		}
	}
}
