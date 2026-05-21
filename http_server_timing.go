package main

import (
	"strconv"
	"strings"
)

// Server-Timing header parser. Defined in W3C Server-Timing spec (a stable
// Recommendation). Servers emit per-component timing as a comma-separated
// list of `name;dur=<ms>;desc="<text>"` entries — the same structure browsers
// render in DevTools' "Server Timing" tab.
//
// Example header:
//
//	Server-Timing: db;dur=53.2;desc="Postgres", cache;dur=2.5, total;dur=120
//
// netdoc renders these as a sub-table in the HTTP check so users can see
// per-component breakdown of server-side cost. No CLI surfaces this cleanly —
// curl prints the raw header, browsers show it visually, netdoc gives a
// scriptable parsed form.

// serverTimingEntry is one parsed component.
type serverTimingEntry struct {
	Name string  `json:"name"`
	Dur  float64 `json:"dur_ms,omitempty"`
	Desc string  `json:"desc,omitempty"`
}

// parseServerTiming splits a Server-Timing header value into entries.
// Whitespace around tokens is tolerated. Empty entries are skipped.
func parseServerTiming(header string) []serverTimingEntry {
	if header == "" {
		return nil
	}
	var out []serverTimingEntry
	for _, raw := range strings.Split(header, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, ";")
		entry := serverTimingEntry{Name: strings.TrimSpace(parts[0])}
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			switch k {
			case "dur":
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					entry.Dur = f
				}
			case "desc":
				// Strip surrounding quotes if present.
				v = strings.TrimPrefix(v, "\"")
				v = strings.TrimSuffix(v, "\"")
				entry.Desc = v
			}
		}
		if entry.Name != "" {
			out = append(out, entry)
		}
	}
	return out
}

// serverTimingHeadline returns "Server-Timing: db 53ms, cache 2ms" for the
// hint line. Caps at 3 entries to keep the line readable.
func serverTimingHeadline(entries []serverTimingEntry) string {
	if len(entries) == 0 {
		return ""
	}
	shown := entries
	more := 0
	if len(shown) > 3 {
		more = len(shown) - 3
		shown = shown[:3]
	}
	var parts []string
	for _, e := range shown {
		label := e.Name
		if e.Dur > 0 {
			if e.Dur < 1 {
				label += " <1ms"
			} else {
				label += " " + itoa(int(e.Dur+0.5)) + "ms"
			}
		}
		parts = append(parts, label)
	}
	out := "Server-Timing: " + strings.Join(parts, ", ")
	if more > 0 {
		out += " +" + itoa(more) + " more"
	}
	return out
}
