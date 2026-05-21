package main

import "regexp"

// Banner-pattern service version detection — a curated subset of what nmap's
// service-probes database does, scoped to TCP services that greet on connect
// with a parseable banner. nmap-services-probes covers thousands of probes;
// we cover the handful that fire reliably without needing per-protocol probe
// strings, which is the right scope for a one-command diagnostic.

// bannerRule is one parse rule: a regex that, if matched, yields a Product
// and Version. When `Product` is set, the rule's group 1 is the version; when
// `Product` is empty the regex captures product in group 1 and version in
// group 2.
type bannerRule struct {
	Re      *regexp.Regexp
	Product string
}

// bannerRules is iterated top-to-bottom; first match wins. Order is roughly
// by specificity — narrower banners first.
var bannerRules = []bannerRule{
	// SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	//       "SSH-2.0-libssh_0.10.4"
	//       "SSH-2.0-dropbear_2022.83"
	// product = before the underscore, version = after.
	{Re: regexp.MustCompile(`^SSH-\d+\.\d+-([A-Za-z][A-Za-z0-9]*)[_ ]([0-9][\w.+\-]*)`)},

	// SMTP banners often look like: "220 mx.example.com ESMTP Postfix (Ubuntu)"
	// or "220 mx ESMTP Exim 4.94". Capture daemon + optional version.
	{Re: regexp.MustCompile(`ESMTP (Postfix|Exim|Sendmail|qmail|OpenSMTPD|Microsoft ESMTP)(?:\s+([0-9][\w.]*))?`)},

	// FTP — vsFTPd / ProFTPD / Pure-FTPd / FileZilla advertise in parentheses.
	// "220 (vsFTPd 3.0.3)" / "220 ProFTPD 1.3.7 Server"
	{Re: regexp.MustCompile(`\(?(vsFTPd|ProFTPD|FileZilla Server|Pure-FTPd|Microsoft FTP)\s+([0-9][\w.+\-]*)\)?`)},

	// IMAP — Dovecot / Cyrus / Courier
	// "* OK [CAPABILITY ...] Dovecot ready."
	{Re: regexp.MustCompile(`(Dovecot|Cyrus IMAP|Courier-IMAP|Microsoft Exchange)`), Product: ""}, // product captured, version empty

	// POP3 — same daemons usually
	// "+OK Dovecot (Ubuntu) ready."
	// (covered by the IMAP rule above for Dovecot)

	// VNC: "RFB 003.008\n"
	{Re: regexp.MustCompile(`^RFB (\d{3}\.\d{3})`), Product: "VNC"},

	// MySQL: server greets with a binary handshake whose ASCII fragment is
	// usually a recognizable version like "8.0.32-MySQL Community Server".
	{Re: regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)[\-\w]*(MySQL|MariaDB)`)},

	// Redis ACL'd: server replies with "-NOAUTH Authentication required."
	// (no version on the wire) — skip; raw banner is informative enough.

	// MongoDB: greets with binary, no parseable banner.

	// Telnet: usually starts with IAC bytes followed by login prompt.

	// SMTP fallback — just capture the hello domain
	// "220 mail.example.com SMTP service ready"
	// (no high-confidence product extraction; skip)
}

// parseBanner inspects the captured banner and returns product + version when
// a rule matches. Returns ("", "") when no rule applies — callers fall back
// to rendering the truncated raw banner.
func parseBanner(banner string) (product, version string) {
	if banner == "" {
		return "", ""
	}
	for _, rule := range bannerRules {
		m := rule.Re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		if rule.Product != "" {
			// Pinned product; group 1 is version (if any).
			if len(m) >= 2 {
				return rule.Product, m[1]
			}
			return rule.Product, ""
		}
		// Product captured in group 1, version in group 2 (when present).
		if len(m) >= 3 {
			return m[1], m[2]
		}
		if len(m) >= 2 {
			return m[1], ""
		}
	}
	return "", ""
}
