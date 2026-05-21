package main

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Extended discovery probes — WebAuthn / FIDO2, SAML metadata, and
// WebTransport. Hits in parallel with the existing OIDC/OAuth/security.txt
// probes via the same /.well-known scaffolding.
//
// What we look for:
//
//   /.well-known/webauthn          — RFC draft, FIDO2 metadata endpoint
//   /.well-known/passkey-endpoints — Apple passkey relying-party discovery
//   /metadata or /federationmetadata.xml — SAML 2.0 IDP/SP metadata
//   /.well-known/host-meta         — XRD, sometimes points to SAML metadata
//   /.well-known/webtransport      — IETF draft, WebTransport-over-HTTP/3 advert
//
// These don't gate any health verdict — they're posture intelligence
// surfaced in the JSON output and in the Discovery check's hint when
// found.

// extendedDiscoveryResult holds the additional findings.
type extendedDiscoveryResult struct {
	WebAuthnEndpoint   string   `json:"webauthn_endpoint,omitempty"`
	PasskeyEndpoint    string   `json:"passkey_endpoint,omitempty"`
	SAMLMetadataURL    string   `json:"saml_metadata_url,omitempty"`
	SAMLEntityID       string   `json:"saml_entity_id,omitempty"`
	SAMLRoles          []string `json:"saml_roles,omitempty"` // IDP / SP / both
	WebTransportFound  bool     `json:"webtransport_advertised,omitempty"`
	HostMetaFound      bool     `json:"host_meta_advertised,omitempty"`
}

// probeExtendedDiscovery runs the additional probes concurrently.
func probeExtendedDiscovery(scheme, host string, port int, timeout time.Duration) extendedDiscoveryResult {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	base := fmt.Sprintf("%s://%s", scheme, host)
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		base = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}

	out := extendedDiscoveryResult{}
	var mu sync.Mutex
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	probe := func(path string, handler func(body []byte, status int, headers http.Header)) {
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		handler(body, resp.StatusCode, resp.Header)
	}

	var wg sync.WaitGroup
	wg.Add(5)
	// WebAuthn — JSON or just-presence detection at /.well-known/webauthn.
	go func() {
		defer wg.Done()
		probe("/.well-known/webauthn", func(body []byte, status int, _ http.Header) {
			if status != http.StatusOK || len(body) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			out.WebAuthnEndpoint = base + "/.well-known/webauthn"
		})
	}()
	// Apple passkey endpoint discovery.
	go func() {
		defer wg.Done()
		probe("/.well-known/passkey-endpoints", func(body []byte, status int, _ http.Header) {
			if status != http.StatusOK || len(body) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			out.PasskeyEndpoint = base + "/.well-known/passkey-endpoints"
		})
	}()
	// SAML federation metadata — common paths for Microsoft/ADFS/Shibboleth.
	go func() {
		defer wg.Done()
		// Try the most common path first, then fall back. We stop at the
		// first hit to avoid wasting requests.
		paths := []string{"/FederationMetadata/2007-06/FederationMetadata.xml", "/metadata", "/sso/saml/metadata", "/saml/metadata"}
		for _, p := range paths {
			done := false
			probe(p, func(body []byte, status int, _ http.Header) {
				if status != http.StatusOK || len(body) == 0 {
					return
				}
				if entityID, roles := parseSAMLMetadata(body); entityID != "" {
					mu.Lock()
					out.SAMLMetadataURL = base + p
					out.SAMLEntityID = entityID
					out.SAMLRoles = roles
					mu.Unlock()
					done = true
				}
			})
			if done {
				break
			}
		}
	}()
	// WebTransport advertisement.
	go func() {
		defer wg.Done()
		probe("/.well-known/webtransport", func(body []byte, status int, _ http.Header) {
			if status == http.StatusOK {
				mu.Lock()
				defer mu.Unlock()
				out.WebTransportFound = true
			}
		})
	}()
	// host-meta — XRD format, RFC 6415.
	go func() {
		defer wg.Done()
		probe("/.well-known/host-meta", func(body []byte, status int, _ http.Header) {
			if status == http.StatusOK && len(body) > 0 {
				mu.Lock()
				defer mu.Unlock()
				out.HostMetaFound = true
			}
		})
	}()
	wg.Wait()
	return out
}

// parseSAMLMetadata cracks open a SAML 2.0 metadata XML document and
// returns (entityID, roles). Roles is some subset of {"IDPSSODescriptor",
// "SPSSODescriptor", "AttributeAuthorityDescriptor", ...} — we only need
// to detect IDP vs SP for posture purposes.
func parseSAMLMetadata(b []byte) (string, []string) {
	// We don't fully unmarshal; just stream tokens and pick out the
	// EntityDescriptor entityID attribute + role-element local names.
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	var entityID string
	var roles []string
	roleSeen := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "EntityDescriptor":
				for _, attr := range t.Attr {
					if attr.Name.Local == "entityID" {
						entityID = attr.Value
					}
				}
			case "IDPSSODescriptor", "SPSSODescriptor", "AttributeAuthorityDescriptor", "AuthnAuthorityDescriptor", "PDPDescriptor":
				if !roleSeen[t.Name.Local] {
					roleSeen[t.Name.Local] = true
					roles = append(roles, t.Name.Local)
				}
			}
		}
		if entityID != "" && len(roles) >= 2 {
			break // good enough; stop streaming
		}
	}
	return entityID, roles
}
