package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTP-discovery probes. Hits a small curated list of /.well-known endpoints
// in parallel and surfaces what the server exposes about itself. These probes
// are visible diagnostic value for:
//   - SSO/identity targets: OIDC + OAuth metadata reveals issuer, endpoints
//   - any site: security.txt reveals the security-contact (RFC 9116)
//   - many APIs: WWW-Authenticate header tells you the auth scheme(s) used
//
// Each probe is GET with a 2-second cap and runs concurrently with the others.

// discoveryResult collects per-endpoint findings.
type discoveryResult struct {
	OIDCIssuer      string   `json:"oidc_issuer,omitempty"`
	OAuthIssuer     string   `json:"oauth_issuer,omitempty"`
	SecurityTxt     bool     `json:"security_txt,omitempty"`
	SecurityContact string   `json:"security_contact,omitempty"`
	WWWAuthSchemes  []string `json:"www_auth_schemes,omitempty"`
	ChangePassword  string   `json:"change_password,omitempty"`
}

// probeDiscovery runs the well-known probes concurrently and returns whatever
// the server surfaced. Missing endpoints are silently absent from the result.
func probeDiscovery(scheme, host string, port int, timeout time.Duration, wwwAuth string) discoveryResult {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	base := fmt.Sprintf("%s://%s", scheme, host)
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		base = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}

	out := discoveryResult{}
	if wwwAuth != "" {
		out.WWWAuthSchemes = parseWWWAuthSchemes(wwwAuth)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: timeout,
		// Skip cert verification on these probes — we're not validating the
		// site, just discovering metadata; the main TLS check covers cert
		// validity. Without this, expired-cert targets fail every probe.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	probe := func(path string, handle func(b []byte) (string, string)) {
		defer wg.Done()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "netdoc/"+version)
		req.Header.Set("Accept", "*/*")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		if err != nil {
			return
		}
		key, value := handle(body)
		mu.Lock()
		defer mu.Unlock()
		switch key {
		case "oidc":
			out.OIDCIssuer = value
		case "oauth":
			out.OAuthIssuer = value
		case "security":
			out.SecurityTxt = true
			out.SecurityContact = value
		case "change":
			out.ChangePassword = base + path
		}
	}

	wg.Add(4)
	go probe("/.well-known/openid-configuration", parseIssuerJSON("oidc"))
	go probe("/.well-known/oauth-authorization-server", parseIssuerJSON("oauth"))
	go probe("/.well-known/security.txt", parseSecurityTxt)
	go probe("/.well-known/change-password", func(_ []byte) (string, string) { return "change", "" })
	wg.Wait()
	return out
}

// parseIssuerJSON returns a handler that extracts the `issuer` field from
// JSON metadata published at OIDC / OAuth-AS discovery endpoints.
func parseIssuerJSON(kind string) func(b []byte) (string, string) {
	return func(b []byte) (string, string) {
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return "", ""
		}
		if doc.Issuer == "" {
			return "", ""
		}
		return kind, doc.Issuer
	}
}

// parseSecurityTxt extracts the first Contact: line from an RFC 9116
// security.txt file. The file is plain text with key: value lines.
func parseSecurityTxt(b []byte) (string, string) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "contact:") {
			val := strings.TrimSpace(line[len("contact:"):])
			return "security", truncate(val, 60)
		}
	}
	return "security", ""
}

// parseWWWAuthSchemes returns the list of auth schemes from a WWW-Authenticate
// header value. The header may carry multiple comma-separated challenges, each
// like "Basic realm=...", "Bearer ...", "Digest ...". We just want the scheme
// names.
func parseWWWAuthSchemes(value string) []string {
	var schemes []string
	seen := map[string]bool{}
	for _, ch := range strings.Split(value, ",") {
		ch = strings.TrimSpace(ch)
		if ch == "" {
			continue
		}
		// Scheme is the first token (up to whitespace or '=').
		end := len(ch)
		for i, c := range ch {
			if c == ' ' || c == '=' {
				end = i
				break
			}
		}
		scheme := ch[:end]
		if scheme == "" {
			continue
		}
		// Capitalise consistently: Basic / Bearer / Digest / Negotiate / ...
		canon := strings.ToUpper(scheme[:1]) + strings.ToLower(scheme[1:])
		if !seen[canon] {
			seen[canon] = true
			schemes = append(schemes, canon)
		}
	}
	return schemes
}

// checkDiscovery runs the well-known probes against the target and reports
// what was found. Skipped when DNS failed or when the target isn't HTTP(S).
func (d *diagnosis) checkDiscovery() Check {
	c := Check{Name: "Discovery"}
	if !d.resolved {
		c.Status = StatusSkip
		c.Summary = "skipped — DNS did not resolve"
		return c
	}
	if d.scheme != "http" && d.scheme != "https" {
		c.Status = StatusSkip
		c.Summary = "skipped — non-HTTP target"
		return c
	}

	wwwAuth := ""
	if d.trace != nil && d.trace.Headers != nil {
		wwwAuth = d.trace.Headers.Get("WWW-Authenticate")
	}

	// Run core /.well-known probes (OIDC, OAuth-AS, security.txt,
	// change-password) and extended probes (WebAuthn, SAML, WebTransport,
	// host-meta) concurrently. Both share the same HTTP-client / timeout
	// budget for fairness.
	var res discoveryResult
	var ext extendedDiscoveryResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		res = probeDiscovery(d.scheme, d.host, d.port, d.timeout, wwwAuth)
	}()
	go func() {
		defer wg.Done()
		ext = probeExtendedDiscovery(d.scheme, d.host, d.port, d.timeout)
	}()
	wg.Wait()

	// Collect what we found into a slice of "label: value" lines.
	var found []string
	if res.OIDCIssuer != "" {
		found = append(found, "OIDC issuer: "+truncate(res.OIDCIssuer, 44))
	}
	if res.OAuthIssuer != "" {
		found = append(found, "OAuth AS: "+truncate(res.OAuthIssuer, 44))
	}
	if res.SecurityTxt {
		label := "security.txt"
		if res.SecurityContact != "" {
			label = "security.txt: " + truncate(res.SecurityContact, 44)
		}
		found = append(found, label)
	}
	if res.ChangePassword != "" {
		found = append(found, "change-password endpoint advertised")
	}
	if len(res.WWWAuthSchemes) > 0 {
		found = append(found, "auth scheme: "+strings.Join(res.WWWAuthSchemes, ", "))
	}
	if ext.WebAuthnEndpoint != "" {
		found = append(found, "WebAuthn/FIDO2 endpoint advertised")
	}
	if ext.PasskeyEndpoint != "" {
		found = append(found, "Apple passkey endpoint advertised")
	}
	if ext.SAMLEntityID != "" {
		roleStr := ""
		if len(ext.SAMLRoles) > 0 {
			roleStr = " (" + strings.Join(ext.SAMLRoles, "/") + ")"
		}
		found = append(found, "SAML"+roleStr+": "+truncate(ext.SAMLEntityID, 44))
	}
	if ext.WebTransportFound {
		found = append(found, "WebTransport advertised")
	}
	if ext.HostMetaFound {
		found = append(found, "host-meta (XRD) advertised")
	}

	c.Detail = map[string]any{
		"oidc_issuer":           res.OIDCIssuer,
		"oauth_issuer":          res.OAuthIssuer,
		"security_txt":          res.SecurityTxt,
		"security_contact":      res.SecurityContact,
		"www_auth_schemes":      res.WWWAuthSchemes,
		"change_password":       res.ChangePassword,
		"webauthn_endpoint":     ext.WebAuthnEndpoint,
		"passkey_endpoint":      ext.PasskeyEndpoint,
		"saml_metadata_url":     ext.SAMLMetadataURL,
		"saml_entity_id":        ext.SAMLEntityID,
		"saml_roles":            ext.SAMLRoles,
		"webtransport":          ext.WebTransportFound,
		"host_meta":             ext.HostMetaFound,
	}

	if len(found) == 0 {
		c.Status = StatusSkip
		c.Summary = "no well-known endpoints exposed"
		return c
	}
	c.Status = StatusOK
	c.Summary = fmt.Sprintf("%d discovery resource%s exposed", len(found), plural(len(found)))
	c.Hint = strings.Join(found, "\n")
	return c
}
