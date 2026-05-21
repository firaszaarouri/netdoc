package main

import (
	"strings"
	"testing"
)

// Tests for HTTP-layer parsers and the HTML body scanner.

// --- Server-Timing parser tests ---

func TestParseServerTiming_Empty(t *testing.T) {
	if got := parseServerTiming(""); got != nil {
		t.Errorf("empty header: got %v want nil", got)
	}
}

func TestParseServerTiming_SingleEntry(t *testing.T) {
	got := parseServerTiming("db;dur=53.2")
	if len(got) != 1 {
		t.Fatalf("len: got %d want 1", len(got))
	}
	if got[0].Name != "db" {
		t.Errorf("name: got %q want db", got[0].Name)
	}
	if got[0].Dur != 53.2 {
		t.Errorf("dur: got %v want 53.2", got[0].Dur)
	}
}

func TestParseServerTiming_WithDescription(t *testing.T) {
	got := parseServerTiming(`db;dur=53.2;desc="Postgres pool"`)
	if len(got) != 1 || got[0].Desc != "Postgres pool" {
		t.Errorf("desc: got %v want Postgres pool", got)
	}
}

func TestParseServerTiming_MultipleEntries(t *testing.T) {
	got := parseServerTiming(`db;dur=53.2;desc="Postgres", cache;dur=2.5, total;dur=120`)
	if len(got) != 3 {
		t.Fatalf("len: got %d want 3", len(got))
	}
	if got[0].Name != "db" || got[1].Name != "cache" || got[2].Name != "total" {
		t.Errorf("names: %v", got)
	}
	if got[2].Dur != 120 {
		t.Errorf("third dur: got %v want 120", got[2].Dur)
	}
}

func TestParseServerTiming_WhitespaceAndOrder(t *testing.T) {
	// Whitespace around tokens is tolerated; key order within an entry
	// can be desc-first or dur-first.
	got := parseServerTiming(`  cache ; desc = "edge"  ;  dur = 4.0  `)
	if len(got) != 1 {
		t.Fatalf("len: got %d want 1", len(got))
	}
	if got[0].Name != "cache" || got[0].Dur != 4.0 || got[0].Desc != "edge" {
		t.Errorf("got %+v", got[0])
	}
}

func TestParseServerTiming_NoEntries(t *testing.T) {
	// Whitespace-only or commas-only input.
	if got := parseServerTiming(", , ,"); len(got) != 0 {
		t.Errorf("commas-only: got %d entries, want 0", len(got))
	}
}

func TestParseServerTiming_DurMissingValue(t *testing.T) {
	// Entry with malformed dur — should fall back to zero, not crash.
	got := parseServerTiming(`db;dur=`)
	if len(got) != 1 || got[0].Name != "db" || got[0].Dur != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestServerTimingHeadline_Empty(t *testing.T) {
	if got := serverTimingHeadline(nil); got != "" {
		t.Errorf("empty entries: got %q want empty", got)
	}
}

func TestServerTimingHeadline_Caps3(t *testing.T) {
	entries := []serverTimingEntry{
		{Name: "a", Dur: 10},
		{Name: "b", Dur: 20},
		{Name: "c", Dur: 30},
		{Name: "d", Dur: 40},
		{Name: "e", Dur: 50},
	}
	got := serverTimingHeadline(entries)
	if !strings.Contains(got, "+2 more") {
		t.Errorf("expected +2 more for >3 entries, got %q", got)
	}
	// First three should be in the output.
	for _, name := range []string{"a", "b", "c"} {
		if !strings.Contains(got, name) {
			t.Errorf("missing entry %q in %q", name, got)
		}
	}
}

func TestServerTimingHeadline_SubMillisecond(t *testing.T) {
	entries := []serverTimingEntry{{Name: "fast", Dur: 0.4}}
	got := serverTimingHeadline(entries)
	if !strings.Contains(got, "<1ms") {
		t.Errorf("sub-ms should render as <1ms, got %q", got)
	}
}

// --- HTML scanner tests ---

func TestScanHTML_SRIComplete(t *testing.T) {
	body := []byte(`
<html><head>
  <script src="https://cdn.example.com/lib.js" integrity="sha384-abc"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha384-def">
</head><body></body></html>`)
	res := scanHTML(body, "https", "page.example.com")
	if res.ExternalScripts != 1 || res.ScriptsWithSRI != 1 {
		t.Errorf("external scripts=%d sri=%d want 1/1", res.ExternalScripts, res.ScriptsWithSRI)
	}
	if res.ExternalStyles != 1 || res.StylesWithSRI != 1 {
		t.Errorf("external styles=%d sri=%d want 1/1", res.ExternalStyles, res.StylesWithSRI)
	}
	if len(res.MissingSRI) > 0 {
		t.Errorf("MissingSRI should be empty, got %v", res.MissingSRI)
	}
}

func TestScanHTML_MissingSRI(t *testing.T) {
	body := []byte(`<script src="https://cdn.example.com/lib.js"></script>`)
	res := scanHTML(body, "https", "page.example.com")
	if res.ExternalScripts != 1 || res.ScriptsWithSRI != 0 {
		t.Errorf("expected 1 external 0 with SRI, got %d/%d", res.ExternalScripts, res.ScriptsWithSRI)
	}
	if len(res.MissingSRI) != 1 {
		t.Errorf("MissingSRI: %v", res.MissingSRI)
	}
}

func TestScanHTML_MixedContent(t *testing.T) {
	// HTTPS page loading an HTTP script — classic mixed-content.
	body := []byte(`<script src="http://insecure.example.com/lib.js"></script>`)
	res := scanHTML(body, "https", "page.example.com")
	if len(res.MixedContent) != 1 {
		t.Errorf("MixedContent: got %v want 1 entry", res.MixedContent)
	}
}

func TestScanHTML_NoMixedContentOnHTTPPage(t *testing.T) {
	// Same script on an HTTP page is not mixed-content (the whole page is HTTP).
	body := []byte(`<script src="http://insecure.example.com/lib.js"></script>`)
	res := scanHTML(body, "http", "page.example.com")
	if len(res.MixedContent) != 0 {
		t.Errorf("HTTP page shouldn't trigger mixed-content, got %v", res.MixedContent)
	}
}

func TestScanHTML_InsecureForm(t *testing.T) {
	body := []byte(`<form action="http://example.com/submit"><input name="pw" type="password"></form>`)
	res := scanHTML(body, "https", "page.example.com")
	if len(res.InsecureForms) != 1 {
		t.Errorf("InsecureForms: %v", res.InsecureForms)
	}
}

func TestScanHTML_IframeWithoutSandbox(t *testing.T) {
	body := []byte(`<iframe src="https://third-party.example.com/widget"></iframe>`)
	res := scanHTML(body, "https", "page.example.com")
	if len(res.IframesUntrusted) != 1 {
		t.Errorf("untrusted iframe count: %v", res.IframesUntrusted)
	}
}

func TestScanHTML_IframeWithSandbox(t *testing.T) {
	body := []byte(`<iframe src="https://third-party.example.com/widget" sandbox></iframe>`)
	res := scanHTML(body, "https", "page.example.com")
	if len(res.IframesUntrusted) != 0 {
		t.Errorf("sandboxed iframe should not flag, got %v", res.IframesUntrusted)
	}
}

func TestScanHTML_FirstPartyScriptSkipped(t *testing.T) {
	// Script with the SAME host as the page — first-party, doesn't need SRI.
	body := []byte(`<script src="/local/lib.js"></script><script src="https://page.example.com/lib2.js"></script>`)
	res := scanHTML(body, "https", "page.example.com")
	if res.ExternalScripts != 0 {
		t.Errorf("first-party scripts: %d should be skipped from external count", res.ExternalScripts)
	}
}

func TestScanHTML_EmptyBody(t *testing.T) {
	res := scanHTML(nil, "https", "example.com")
	if res.ExternalScripts != 0 || len(res.MixedContent) != 0 {
		t.Errorf("empty body should produce empty result")
	}
}

func TestIsExternalURL(t *testing.T) {
	cases := []struct {
		url      string
		pageHost string
		want     bool
	}{
		{"/relative/path.js", "example.com", false},
		{"https://example.com/path.js", "example.com", false},
		{"https://cdn.example.org/lib.js", "example.com", true},
		{"//cdn.example.org/lib.js", "example.com", true}, // protocol-relative
		{"data:application/javascript,alert(1)", "example.com", false}, // inline data
	}
	for _, c := range cases {
		got := isExternalURL(c.url, c.pageHost)
		if got != c.want {
			t.Errorf("url=%q pageHost=%q: got %v want %v", c.url, c.pageHost, got, c.want)
		}
	}
}
