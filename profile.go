package main

import (
	"fmt"
	"strings"
)

// --check and --profile filtering. Both narrow the 14-check pipeline so
// users can trade depth for speed (fast probes against many hosts) or
// focus (only TLS, only mail) without modifying the source.
//
// Implementation: runAllChecks consults checkFilter to decide whether
// to run each check. The filter is a set of check names (lowercased)
// plus convenience presets.

// canonicalCheckNames is the set of valid --check tokens. Match what
// each check returns from its Name field (lowercased here, the actual
// Check.Name preserves capitalization).
var canonicalCheckNames = map[string]bool{
	"dns":        true,
	"domain":     true,
	"delegation": true,
	"tcp":        true,
	"latency":    true,
	"path":       true,
	"tls":        true,
	"http":       true,
	"security":   true,
	"discovery":  true,
	"mail":       true,
	"reputation": true,
	"ipv6":       true,
	"ports":      true,
}

// profilePresets define curated check sets for common use cases.
var profilePresets = map[string][]string{
	"fast": {
		// Sub-second posture snapshot: just the connectivity essentials.
		// Skip RDAP/delegation (rate-limited servers), path (30 probes),
		// mail (per-MX iteration), reputation (116 DNSBLs + FCrDNS), ports.
		"dns", "tcp", "tls", "http",
	},
	"web": {
		// Web-focused full posture without mail / reputation.
		"dns", "tcp", "latency", "tls", "http", "security", "discovery", "ipv6",
	},
	"mail": {
		// Mail-server focus: skip HTTP-layer checks.
		"dns", "domain", "tcp", "tls", "mail", "reputation", "ipv6",
	},
	"full": {
		// Everything except --ports (which the user opts into separately).
		"dns", "domain", "delegation", "tcp", "latency", "path", "tls",
		"http", "security", "discovery", "mail", "reputation", "ipv6",
	},
	"paranoid": {
		// Full + ports + every optional posture probe. Same checks as full
		// for now — flag exists so users can signal "thorough" intent and
		// future probes can gate themselves on it. The diagnosis struct's
		// ports field controls whether Ports check runs; this preset
		// doesn't auto-enable port scanning (that would be surprising).
		"dns", "domain", "delegation", "tcp", "latency", "path", "tls",
		"http", "security", "discovery", "mail", "reputation", "ipv6", "ports",
	},
}

// checkFilter holds the active set of allowed check names. Empty set
// means "all checks" (default behavior preserved).
type checkFilter struct {
	allow map[string]bool
}

// allowsAll returns true when no filtering is in effect.
func (f *checkFilter) allowsAll() bool {
	return f == nil || len(f.allow) == 0
}

// permits returns whether the named check should run. Comparison is
// case-insensitive against the lowercased name.
func (f *checkFilter) permits(name string) bool {
	if f.allowsAll() {
		return true
	}
	return f.allow[strings.ToLower(name)]
}

// parseCheckFilter builds a filter from a comma-separated list. Returns
// an error on unrecognized tokens — typos shouldn't silently produce
// no-op scans.
//
// Auto-adds "dns" when the filter includes any check that depends on
// resolved IPs from DNS (everything except domain + delegation, which
// query the public DNS hierarchy directly). Without this, --check tls
// produces an opaque "skipped — DNS did not resolve" verdict that
// confuses first-time users.
func parseCheckFilter(spec string) (*checkFilter, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return &checkFilter{}, nil
	}
	allow := make(map[string]bool)
	for _, tok := range strings.Split(spec, ",") {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "" {
			continue
		}
		if !canonicalCheckNames[t] {
			return nil, fmt.Errorf("--check: unknown name %q (valid: dns, domain, delegation, tcp, latency, path, tls, http, security, discovery, mail, reputation, ipv6, ports)", t)
		}
		allow[t] = true
	}
	addDNSDependencyIfNeeded(allow)
	return &checkFilter{allow: allow}, nil
}

// addDNSDependencyIfNeeded silently adds "dns" to the filter when any
// IP-dependent check is requested. Checks that DON'T depend on DNS
// resolution (domain via RDAP, delegation via direct queries, dns itself)
// don't trigger the auto-add.
func addDNSDependencyIfNeeded(allow map[string]bool) {
	if allow["dns"] {
		return
	}
	for _, dep := range []string{"tcp", "latency", "path", "tls", "http", "security", "discovery", "mail", "reputation", "ipv6", "ports"} {
		if allow[dep] {
			allow["dns"] = true
			return
		}
	}
}

// parseProfile resolves a preset name to its check list. Returns an
// error on unknown preset.
func parseProfile(name string) (*checkFilter, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	preset, ok := profilePresets[name]
	if !ok {
		var available []string
		for k := range profilePresets {
			available = append(available, k)
		}
		return nil, fmt.Errorf("--profile: unknown preset %q (valid: %s)", name, strings.Join(available, ", "))
	}
	allow := make(map[string]bool, len(preset))
	for _, c := range preset {
		allow[c] = true
	}
	addDNSDependencyIfNeeded(allow)
	return &checkFilter{allow: allow}, nil
}
