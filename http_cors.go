package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// CORS misconfiguration probe. Sends a GET (and optionally OPTIONS preflight)
// carrying an Origin header that the server should never reflect. The classic
// misconfig classes:
//
//   • `Access-Control-Allow-Origin: *` AND `Allow-Credentials: true` — invalid
//     per spec but commonly seen; allows ANY origin to read responses while
//     sending the user's cookies.
//   • `Access-Control-Allow-Origin: <our-fake-origin>` (echoed back) AND
//     `Allow-Credentials: true` — same effect, more dangerous because some
//     deployments echo any Origin without validation.
//   • `Access-Control-Allow-Origin: null` — accepts null origin, allowing
//     attacker pages loaded via data: / sandboxed iframes / local files.
//
// Reference: https://portswigger.net/web-security/cors

// corsResult records the verdict.
type corsResult struct {
	Probed             bool   `json:"probed"`
	AllowOrigin        string `json:"allow_origin,omitempty"`
	AllowCredentials   bool   `json:"allow_credentials,omitempty"`
	Vary               string `json:"vary,omitempty"`
	EchoesOrigin       bool   `json:"echoes_origin,omitempty"`
	WildcardOrigin     bool   `json:"wildcard_origin,omitempty"`
	NullOriginAccepted bool   `json:"null_origin_accepted,omitempty"`
	Misconfig          string `json:"misconfig,omitempty"` // human-readable verdict
}

// probeCORS sends a GET with Origin: https://netdoc-cors-probe.invalid and
// checks for reflective / credential-leaking misconfigs.
func probeCORS(scheme, host string, port int, timeout time.Duration) corsResult {
	res := corsResult{}
	url := scheme + "://" + host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		url += ":" + itoa(port)
	}
	url += "/"

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Probe 1: arbitrary Origin to check for echo / wildcard
	fakeOrigin := "https://netdoc-cors-probe.invalid"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", "netdoc/2.11")
	req.Header.Set("Origin", fakeOrigin)
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	res.Probed = true
	res.AllowOrigin = resp.Header.Get("Access-Control-Allow-Origin")
	res.AllowCredentials = strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	res.Vary = resp.Header.Get("Vary")
	res.WildcardOrigin = res.AllowOrigin == "*"
	res.EchoesOrigin = res.AllowOrigin == fakeOrigin

	// Probe 2: Origin: null — separate request to avoid cross-talk
	req2, err := http.NewRequest(http.MethodGet, url, nil)
	if err == nil {
		req2.Header.Set("User-Agent", "netdoc/2.11")
		req2.Header.Set("Origin", "null")
		resp2, err := client.Do(req2)
		if err == nil {
			defer resp2.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 4096))
			if resp2.Header.Get("Access-Control-Allow-Origin") == "null" {
				res.NullOriginAccepted = true
			}
		}
	}

	res.Misconfig = classifyCORSMisconfig(res)
	return res
}

// classifyCORSMisconfig returns a human-readable severity verdict, or "" when
// the posture is healthy.
func classifyCORSMisconfig(r corsResult) string {
	switch {
	case r.WildcardOrigin && r.AllowCredentials:
		// Per CORS spec the browser refuses this combo, but the existence
		// of these headers indicates a misconfigured server attempting to
		// leak credentials cross-origin. Some browsers / fetch libraries
		// don't enforce strictly.
		return "wildcard origin AND credentials — invalid + dangerous"
	case r.EchoesOrigin && r.AllowCredentials:
		return "Origin reflected AND credentials enabled — attacker reads response with cookies"
	case r.NullOriginAccepted && r.AllowCredentials:
		return "null origin accepted AND credentials enabled — sandboxed iframe + data URI attack surface"
	case r.EchoesOrigin:
		return "Origin reflected without credentials — limited risk, still a misconfig"
	case r.NullOriginAccepted:
		return "null origin accepted — limited risk without credentials"
	case r.WildcardOrigin:
		return "" // wildcard alone with no credentials is intentional (public APIs)
	}
	return ""
}

// corsHeadline returns the CORS misconfig finding for the hint line. Empty
// when the posture is healthy.
func corsHeadline(r corsResult) string {
	if r.Misconfig == "" {
		return ""
	}
	return "CORS: " + r.Misconfig
}
