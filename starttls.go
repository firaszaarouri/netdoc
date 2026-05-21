package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// STARTTLS — opportunistic TLS upgrade over plaintext SMTP / IMAP / POP3.
// On each MX we probe port 25, capture the banner, send EHLO, look for
// STARTTLS in the EHLO response, then upgrade and capture the peer cert.
// internet.nl and Hardenize both require STARTTLS on every MX as a
// baseline mail-posture pass.
//
// Scope cut: only port 25 (the canonical inbound MX port). Submission
// (587) and submissions (465) are sender-facing and outside what a
// remote-target diagnostic checks.

// mxSTARTTLSResult records the per-MX STARTTLS verdict.
type mxSTARTTLSResult struct {
	Host          string `json:"host"`
	Reachable     bool   `json:"reachable"`
	Banner        string `json:"banner,omitempty"`
	STARTTLSAdvertised bool `json:"starttls_advertised"`
	UpgradeSucceeded   bool `json:"upgrade_succeeded"`
	TLSVersion    string `json:"tls_version,omitempty"`
	CertIssuer    string `json:"cert_issuer,omitempty"`
	CertExpires   string `json:"cert_expires,omitempty"`
	Error         string `json:"error,omitempty"`
}

// probeSTARTTLSForDomain looks up the MX records for a domain and probes
// each one on port 25. Returns a per-MX verdict; failed MXs surface as
// {Reachable: false} with an error string.
func probeSTARTTLSForDomain(domain string, transport *dnsTransport, timeout time.Duration) []mxSTARTTLSResult {
	rrs, err := queryDNS(domain, dns.TypeMX, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return nil
	}
	// Sort by MX preference (low number first) — but for diagnostic purposes
	// the order doesn't matter much; we probe every MX.
	var mxHosts []string
	for _, rr := range rrs {
		if mx, ok := rr.(*dns.MX); ok {
			h := strings.TrimSuffix(mx.Mx, ".")
			if h != "" {
				mxHosts = append(mxHosts, h)
			}
		}
	}
	if len(mxHosts) == 0 {
		return nil
	}

	// Limit MX probes to avoid storming a domain with 20 MX hosts. Three
	// is enough to characterise the deployment.
	if len(mxHosts) > 3 {
		mxHosts = mxHosts[:3]
	}

	perProbe := timeout
	if perProbe > 3*time.Second {
		perProbe = 3 * time.Second
	}

	out := make([]mxSTARTTLSResult, len(mxHosts))
	for i, host := range mxHosts {
		out[i] = probeSTARTTLS(host, perProbe)
	}
	return out
}

// probeSTARTTLS connects to host:25 (SMTP), reads the banner, sends EHLO,
// looks for STARTTLS in the capability list, and upgrades + captures the
// cert info on success.
func probeSTARTTLS(host string, timeout time.Duration) mxSTARTTLSResult {
	r := mxSTARTTLSResult{Host: host}
	addr := net.JoinHostPort(host, strconv.Itoa(25))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		r.Error = "connect: " + tidyErr(err)
		return r
	}
	defer conn.Close()
	r.Reachable = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// SMTP banner — typically "220 mx.example.com ESMTP ..."
	banner, err := readSMTPResponse(reader)
	if err != nil {
		r.Error = "banner: " + tidyErr(err)
		return r
	}
	r.Banner = truncate(strings.TrimSpace(banner), 80)

	// EHLO to negotiate ESMTP. The reply lists capabilities, one per line.
	if _, err := fmt.Fprintf(conn, "EHLO netdoc\r\n"); err != nil {
		r.Error = "EHLO write: " + tidyErr(err)
		return r
	}
	ehloResp, err := readSMTPResponse(reader)
	if err != nil {
		r.Error = "EHLO read: " + tidyErr(err)
		return r
	}
	r.STARTTLSAdvertised = strings.Contains(strings.ToUpper(ehloResp), "STARTTLS")
	if !r.STARTTLSAdvertised {
		return r
	}

	// Upgrade.
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		r.Error = "STARTTLS write: " + tidyErr(err)
		return r
	}
	starttlsResp, err := readSMTPResponse(reader)
	if err != nil {
		r.Error = "STARTTLS read: " + tidyErr(err)
		return r
	}
	if !strings.HasPrefix(strings.TrimSpace(starttlsResp), "220") {
		r.Error = "STARTTLS refused: " + truncate(strings.TrimSpace(starttlsResp), 40)
		return r
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		r.Error = "TLS handshake: " + tidyErr(err)
		return r
	}
	r.UpgradeSucceeded = true
	r.TLSVersion = tlsVersionName(tlsConn.ConnectionState().Version)
	if peers := tlsConn.ConnectionState().PeerCertificates; len(peers) > 0 {
		leaf := peers[0]
		r.CertIssuer = leaf.Issuer.CommonName
		r.CertExpires = leaf.NotAfter.Format("2006-01-02")
	}
	_ = tlsConn.Close()
	return r
}

// readSMTPResponse reads a multi-line SMTP reply. Each line starts with a
// 3-digit code followed by either '-' (more lines coming) or ' ' (final).
func readSMTPResponse(r *bufio.Reader) (string, error) {
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return out.String(), err
		}
		out.WriteString(line)
		if len(line) < 4 {
			break
		}
		if line[3] == ' ' {
			break
		}
	}
	return out.String(), nil
}
