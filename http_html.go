package main

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// HTML body scanner — closes two long-deferred posture columns:
//
//   • Subresource Integrity (SRI) — every <script src=external> or
//     <link rel="stylesheet" href=external> SHOULD carry an integrity=
//     attribute (sha384-... base64) so the browser refuses modified
//     bytes. Tracks third-party CDN supply-chain risk.
//
//   • Mixed content — on an HTTPS page, every external resource URL
//     should start with https:// (or be protocol-relative). Any http://
//     reference downgrades that load, breaks the lock icon, and exposes
//     traffic to MITM. The "mixed content" finding is in Hardenize and
//     Mozilla Observatory's grading.
//
// Uses golang.org/x/net/html — Go's spec-compliant HTML5 tokenizer.
// Inspects up to 64 KB of body (set in trace.go via Content-Type sniff).

// htmlScanResult is the per-page verdict from the HTML scanner.
type htmlScanResult struct {
	ExternalScripts    int      `json:"external_scripts,omitempty"`
	ExternalStyles     int      `json:"external_styles,omitempty"`
	ScriptsWithSRI     int      `json:"scripts_with_sri,omitempty"`
	StylesWithSRI      int      `json:"styles_with_sri,omitempty"`
	MissingSRI         []string `json:"missing_sri,omitempty"`    // external URLs without integrity=
	MixedContent       []string `json:"mixed_content,omitempty"`  // http:// URLs on an https:// page
	InsecureForms      []string `json:"insecure_forms,omitempty"` // <form action="http://...">
	IframesUntrusted   []string `json:"iframes_untrusted,omitempty"` // <iframe> without sandbox=
}

// scanHTML parses the body and returns a posture result. `pageHTTPS` indicates
// whether the page itself was served over HTTPS — if false, mixed-content
// can't apply.
func scanHTML(body []byte, pageScheme, pageHost string) htmlScanResult {
	var res htmlScanResult
	if len(body) == 0 {
		return res
	}
	pageHTTPS := strings.EqualFold(pageScheme, "https")

	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tn, hasAttr := tokenizer.TagName()
		if !hasAttr {
			continue
		}
		tagName := string(tn)
		attrs := map[string]string{}
		for {
			key, val, more := tokenizer.TagAttr()
			attrs[strings.ToLower(string(key))] = string(val)
			if !more {
				break
			}
		}

		switch tagName {
		case "script":
			src := attrs["src"]
			if src == "" {
				continue
			}
			if isExternalURL(src, pageHost) {
				res.ExternalScripts++
				if attrs["integrity"] != "" {
					res.ScriptsWithSRI++
				} else {
					res.MissingSRI = appendCapped(res.MissingSRI, src, 10)
				}
				if pageHTTPS && strings.HasPrefix(strings.ToLower(src), "http://") {
					res.MixedContent = appendCapped(res.MixedContent, src, 10)
				}
			}
		case "link":
			rel := strings.ToLower(attrs["rel"])
			href := attrs["href"]
			if href == "" {
				continue
			}
			// We care about stylesheets + preload as=script/style.
			isStyle := strings.Contains(rel, "stylesheet")
			isPreloadScript := strings.Contains(rel, "preload") && strings.EqualFold(attrs["as"], "script")
			isPreloadStyle := strings.Contains(rel, "preload") && strings.EqualFold(attrs["as"], "style")
			if !isStyle && !isPreloadScript && !isPreloadStyle {
				continue
			}
			if isExternalURL(href, pageHost) {
				if isStyle || isPreloadStyle {
					res.ExternalStyles++
					if attrs["integrity"] != "" {
						res.StylesWithSRI++
					} else {
						res.MissingSRI = appendCapped(res.MissingSRI, href, 10)
					}
				} else {
					res.ExternalScripts++
					if attrs["integrity"] != "" {
						res.ScriptsWithSRI++
					} else {
						res.MissingSRI = appendCapped(res.MissingSRI, href, 10)
					}
				}
				if pageHTTPS && strings.HasPrefix(strings.ToLower(href), "http://") {
					res.MixedContent = appendCapped(res.MixedContent, href, 10)
				}
			}
		case "img", "video", "audio", "source", "track", "embed":
			src := attrs["src"]
			if src == "" {
				continue
			}
			if pageHTTPS && strings.HasPrefix(strings.ToLower(src), "http://") {
				res.MixedContent = appendCapped(res.MixedContent, src, 10)
			}
		case "form":
			action := attrs["action"]
			if pageHTTPS && strings.HasPrefix(strings.ToLower(action), "http://") {
				res.InsecureForms = appendCapped(res.InsecureForms, action, 5)
			}
		case "iframe":
			src := attrs["src"]
			if src == "" {
				continue
			}
			// HTML5 allows `<iframe sandbox>` (valueless attribute) — it
			// activates default-restrictions sandboxing. We must check
			// KEY PRESENCE, not value-non-empty, since the tokenizer
			// stores valueless attributes with value="".
			_, hasSandbox := attrs["sandbox"]
			if isExternalURL(src, pageHost) && !hasSandbox {
				res.IframesUntrusted = appendCapped(res.IframesUntrusted, src, 5)
			}
			if pageHTTPS && strings.HasPrefix(strings.ToLower(src), "http://") {
				res.MixedContent = appendCapped(res.MixedContent, src, 10)
			}
		}
	}
	return res
}

// isExternalURL returns true when the URL points to a different host than
// the page's own host. Relative URLs, hash fragments, and protocol-relative
// URLs that point to the same host are NOT external.
func isExternalURL(rawURL, pageHost string) bool {
	if rawURL == "" || strings.HasPrefix(rawURL, "#") || strings.HasPrefix(rawURL, "data:") || strings.HasPrefix(rawURL, "javascript:") {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Host == "" {
		return false // relative URL — same host
	}
	return !strings.EqualFold(u.Host, pageHost)
}

func appendCapped(s []string, v string, cap int) []string {
	if len(s) >= cap {
		return s
	}
	// Dedupe.
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// htmlScanHeadline summarises the scan for the second hint line. Empty when
// the posture is clean.
func htmlScanHeadline(r htmlScanResult) string {
	var parts []string
	if len(r.MissingSRI) > 0 {
		parts = append(parts, "no SRI on "+itoa(len(r.MissingSRI))+" external "+sriNounPlural(r.ExternalScripts+r.ExternalStyles))
	}
	if len(r.MixedContent) > 0 {
		parts = append(parts, "mixed content×"+itoa(len(r.MixedContent)))
	}
	if len(r.InsecureForms) > 0 {
		parts = append(parts, "insecure form×"+itoa(len(r.InsecureForms)))
	}
	if len(r.IframesUntrusted) > 0 {
		parts = append(parts, "iframe no sandbox×"+itoa(len(r.IframesUntrusted)))
	}
	if r.ExternalScripts > 0 && r.ScriptsWithSRI > 0 && len(r.MissingSRI) == 0 && len(r.MixedContent) == 0 {
		// All-clean positive flag — only when there was actually something to scan.
		parts = append(parts, "SRI: "+itoa(r.ScriptsWithSRI)+"/"+itoa(r.ExternalScripts)+" scripts")
	}
	return strings.Join(parts, "  ·  ")
}

func sriNounPlural(n int) string {
	if n == 1 {
		return "resource"
	}
	return "resources"
}
