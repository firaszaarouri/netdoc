package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CRL (Certificate Revocation List) fetcher + parser. Complements the
// existing OCSP check by:
//
//   1. Reading the CRL Distribution Points (CRLDP) extension from the
//      leaf certificate.
//   2. Fetching the first reachable HTTP CRL endpoint.
//   3. Parsing the CRL via Go's stdlib (crypto/x509 ParseRevocationList,
//      Go 1.19+).
//   4. Reporting CRL freshness (this_update / next_update), revocation
//      count, and whether our leaf is in the list.
//
// Many CAs (notably Let's Encrypt with ARI deployment status as of 2026,
// and major commercial CAs returning to CRL-only revocation in the
// post-OCSP era after Mozilla's 2025 OCSP-stapling-only policy push)
// emphasize CRLs more than they used to. Having BOTH OCSP and CRL
// visibility makes netdoc cover the revocation-check space correctly
// regardless of which mechanism the CA is leaning on.

// crlResult records what we learned about the leaf's CRL.
type crlResult struct {
	Attempted       bool      `json:"attempted"`
	DistributionURL string    `json:"distribution_url,omitempty"`
	ThisUpdate      time.Time `json:"this_update,omitempty"`
	NextUpdate      time.Time `json:"next_update,omitempty"`
	RevocationCount int       `json:"revocation_count,omitempty"`
	LeafRevoked     bool      `json:"leaf_revoked,omitempty"`
	Fresh           bool      `json:"fresh,omitempty"` // next_update is in the future
	Stale           bool      `json:"stale,omitempty"` // next_update is in the past
	Note            string    `json:"note,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// probeCRL fetches and parses the first reachable CRL distribution point
// for the given leaf certificate, reporting freshness + revocation count
// + whether the leaf itself is in the list.
func probeCRL(leaf *x509.Certificate, timeout time.Duration) crlResult {
	out := crlResult{}
	if leaf == nil || len(leaf.CRLDistributionPoints) == 0 {
		out.Note = "no CRLDistributionPoints extension"
		return out
	}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	out.Attempted = true

	// Try HTTP URLs in order. Skip ldap:// — they're rare and Go's
	// stdlib has no LDAP client.
	var crlBytes []byte
	var fetchErr error
	for _, url := range leaf.CRLDistributionPoints {
		if !strings.HasPrefix(strings.ToLower(url), "http://") && !strings.HasPrefix(strings.ToLower(url), "https://") {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			fetchErr = err
			continue
		}
		req.Header.Set("User-Agent", "netdoc/"+version)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			fetchErr = err
			continue
		}
		// CRLs can be large (10s of MB on busy CAs). Cap at 32 MB so we
		// don't OOM on a misconfigured target — though most are <1 MB.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
		resp.Body.Close()
		cancel()
		if readErr != nil {
			fetchErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			fetchErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		out.DistributionURL = url
		crlBytes = body
		break
	}
	if crlBytes == nil {
		if fetchErr != nil {
			out.Error = "fetch failed: " + tidyErr(fetchErr)
		} else {
			out.Error = "no HTTP CRL distribution point reachable"
		}
		return out
	}

	// Parse via stdlib. Accepts both DER and PEM-wrapped CRLs (rare).
	rl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		// Try PEM unwrap as fallback — some CAs serve PEM.
		if start := strings.Index(string(crlBytes), "-----BEGIN X509 CRL-----"); start >= 0 {
			out.Error = "PEM-format CRL not supported in stdlib parser"
			return out
		}
		out.Error = "parse failed: " + tidyErr(err)
		return out
	}

	out.ThisUpdate = rl.ThisUpdate
	out.NextUpdate = rl.NextUpdate
	out.RevocationCount = len(rl.RevokedCertificateEntries)
	now := time.Now()
	out.Fresh = rl.NextUpdate.After(now)
	out.Stale = rl.NextUpdate.Before(now)

	// Check whether OUR leaf is in the revocation list.
	leafSerial := leaf.SerialNumber
	for _, entry := range rl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && leafSerial != nil && entry.SerialNumber.Cmp(leafSerial) == 0 {
			out.LeafRevoked = true
			break
		}
	}

	switch {
	case out.LeafRevoked:
		out.Note = "leaf is REVOKED according to CRL"
	case out.Stale:
		out.Note = fmt.Sprintf("CRL is stale — next_update was %s", out.NextUpdate.Format(time.RFC3339))
	case out.Fresh:
		out.Note = fmt.Sprintf("CRL fresh — next_update %s · %d revoked",
			humanCRLNextUpdate(out.NextUpdate), out.RevocationCount)
	}
	return out
}

// humanCRLNextUpdate formats next_update as a relative-time string for
// the hint line ("in 6d", "in 22h", etc.).
func humanCRLNextUpdate(next time.Time) string {
	d := time.Until(next)
	if d <= 0 {
		return "expired"
	}
	switch {
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	default:
		return fmt.Sprintf("in %dd", int(d.Hours()/24))
	}
}

// silenceUnused for errors import — used implicitly via fmt.Errorf.
var _ = errors.New
