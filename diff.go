package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Baseline diff mode (Hardenize "Regular Monitoring" equivalent). The user
// stores a Report as JSON, re-runs netdoc later, and we emit ONLY the
// differences. Useful for CI gates ("alert when grade drops") and for
// monitoring ("alert when DNS propagation goes split").
//
// Usage:
//   netdoc github.com --json > github.baseline.json
//   ... later ...
//   netdoc github.com --diff github.baseline.json
//
// Output is a curated diff over the high-signal fields, not a full JSON
// patch (which would be too noisy — every timing ms changes between runs).

// diffEntry is one observed change.
type diffEntry struct {
	Path   string `json:"path"`     // e.g. "TLS.grade" or "DNS.propagation.verdict"
	Before string `json:"before"`
	After  string `json:"after"`
}

// reportDiff produces the curated diff between two Reports.
func reportDiff(before, after *Report) []diffEntry {
	var diffs []diffEntry

	if before.Healthy != after.Healthy {
		diffs = append(diffs, diffEntry{
			Path:   "healthy",
			Before: bstr(before.Healthy),
			After:  bstr(after.Healthy),
		})
	}
	if before.FixFirst != after.FixFirst {
		diffs = append(diffs, diffEntry{
			Path:   "fix_first",
			Before: before.FixFirst,
			After:  after.FixFirst,
		})
	}

	beforeChecks := indexChecks(before.Checks)
	afterChecks := indexChecks(after.Checks)

	// Status transitions per-check.
	allNames := mergeCheckNames(beforeChecks, afterChecks)
	for _, name := range allNames {
		b, bok := beforeChecks[name]
		a, aok := afterChecks[name]
		if !bok && aok {
			diffs = append(diffs, diffEntry{
				Path: name + ".status", Before: "(new check)", After: a.Status,
			})
			continue
		}
		if bok && !aok {
			diffs = append(diffs, diffEntry{
				Path: name + ".status", Before: b.Status, After: "(removed)",
			})
			continue
		}
		if b.Status != a.Status {
			diffs = append(diffs, diffEntry{
				Path: name + ".status", Before: b.Status, After: a.Status,
			})
		}
		if b.Summary != a.Summary {
			diffs = append(diffs, diffEntry{
				Path: name + ".summary", Before: b.Summary, After: a.Summary,
			})
		}
		// Curated detail diff — only the high-signal fields.
		diffs = append(diffs, diffCheckDetail(name, b.Detail, a.Detail)...)
	}
	return diffs
}

// diffCheckDetail compares the detail map of one check for the fields we
// care about. Returns a slice of diffs.
func diffCheckDetail(checkName string, before, after map[string]any) []diffEntry {
	var out []diffEntry
	if before == nil && after == nil {
		return out
	}
	// Per-check curated key list — what we actually watch.
	keys := curatedKeysFor(checkName)
	for _, k := range keys {
		bv, aok := stringifyValue(after[k])
		if !aok {
			// after doesn't have the key; check before.
			bv2, bok := stringifyValue(before[k])
			if bok {
				out = append(out, diffEntry{
					Path: checkName + "." + k, Before: bv2, After: "(removed)",
				})
			}
			continue
		}
		bvb, bvbok := stringifyValue(before[k])
		if !bvbok {
			out = append(out, diffEntry{
				Path: checkName + "." + k, Before: "(new)", After: bv,
			})
			continue
		}
		if bvb != bv {
			out = append(out, diffEntry{
				Path: checkName + "." + k, Before: bvb, After: bv,
			})
		}
	}
	return out
}

// curatedKeysFor returns the high-signal detail keys we watch per check.
// Tuned to NOT include timing values that fluctuate naturally between runs.
func curatedKeysFor(checkName string) []string {
	switch checkName {
	case "DNS":
		return []string{"ipv4", "ipv6", "ns", "dnssec_status"}
	case "Domain":
		return []string{"registrar", "expires", "status"}
	case "TLS":
		return []string{"version", "issuer", "expires", "supported_versions", "vulnerabilities", "jarm"}
	case "HTTP":
		return []string{"status", "proto", "redirects", "hsts"}
	case "Security":
		return []string{"score", "grade"}
	case "Mail":
		return []string{"score", "grade"}
	case "Reputation":
		return []string{"hits", "fcrdns"}
	case "IPv6":
		return []string{"has_aaaa", "reachable"}
	}
	return nil
}

// stringifyValue serialises a JSON-friendly value into a short comparable
// string. Returns (value, ok). Falls back to JSON for complex types.
func stringifyValue(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return bstr(x), true
	case float64:
		return fmt.Sprintf("%v", x), true
	case int:
		return fmt.Sprintf("%d", x), true
	case []string:
		sort.Strings(x)
		return strings.Join(x, ","), true
	case []any:
		// JSON unmarshal yields []any even when the field was []string.
		// Coerce element-by-element for stable comparison.
		strs := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				strs = append(strs, s)
			}
		}
		sort.Strings(strs)
		return strings.Join(strs, ","), true
	}
	// Complex value — use JSON.
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// indexChecks builds a name → check map.
func indexChecks(checks []Check) map[string]Check {
	out := make(map[string]Check, len(checks))
	for _, c := range checks {
		out[c.Name] = c
	}
	return out
}

// mergeCheckNames returns the union of check names from two indexes,
// sorted in canonical pipeline order.
func mergeCheckNames(a, b map[string]Check) []string {
	canonical := []string{
		"DNS", "Domain", "Delegation", "TCP", "Latency", "Path",
		"TLS", "HTTP", "Security", "Discovery", "Mail", "Reputation", "IPv6", "Ports",
	}
	have := make(map[string]bool)
	for k := range a {
		have[k] = true
	}
	for k := range b {
		have[k] = true
	}
	var out []string
	for _, name := range canonical {
		if have[name] {
			out = append(out, name)
			delete(have, name)
		}
	}
	// Any unknown checks not in canonical list — append sorted.
	for k := range have {
		out = append(out, k)
	}
	return out
}

// loadBaseline reads a Report from a JSON file.
func loadBaseline(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// renderDiff produces a human-readable diff output.
func renderDiff(diffs []diffEntry, baselinePath string) string {
	var b strings.Builder
	b.WriteString("netdoc diff vs " + baselinePath + "\n")
	b.WriteString(strings.Repeat("─", 60) + "\n")
	if len(diffs) == 0 {
		b.WriteString("(no significant changes)\n")
		return b.String()
	}
	// Group by check.
	byCheck := make(map[string][]diffEntry)
	var order []string
	for _, d := range diffs {
		head, _, _ := strings.Cut(d.Path, ".")
		if _, seen := byCheck[head]; !seen {
			order = append(order, head)
		}
		byCheck[head] = append(byCheck[head], d)
	}
	for _, name := range order {
		b.WriteString("\n" + name + "\n")
		for _, d := range byCheck[name] {
			b.WriteString("  " + d.Path + ":\n")
			b.WriteString("    - " + truncate(d.Before, 80) + "\n")
			b.WriteString("    + " + truncate(d.After, 80) + "\n")
		}
	}
	return b.String()
}

func bstr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
