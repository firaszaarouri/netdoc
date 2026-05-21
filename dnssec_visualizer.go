package main

import (
	"fmt"
	"strings"
)

// ASCII chain visualizer for DNSSEC validation. Renders the
// root → TLD → registrable-domain → leaf walk as a glyph tree using
// box-drawing characters. Pipes cleanly through grep, awk, less,
// and CI logs.

// renderDNSSECChain produces the multi-line ASCII tree for one
// dnssecValidation result. When color is true, ✓ is wrapped in green
// ANSI and ✗ in red. The returned string ends without a trailing newline
// so callers can join it into a hint block as they like.
func renderDNSSECChain(v *dnssecValidation, qname string, color bool) string {
	if v == nil {
		return ""
	}

	check := "✓"
	cross := "✗"
	if color {
		check = "\x1b[32m✓\x1b[0m"
		cross = "\x1b[31m✗\x1b[0m"
	}

	var b strings.Builder
	header := fmt.Sprintf("DNSSEC chain — %s", qname)
	if v.Validated {
		header += " " + check + " validated"
	} else if v.Reason != "" {
		header += " " + cross + " " + v.Reason
	} else {
		header += " " + cross + " not validated"
	}
	b.WriteString(header)
	b.WriteByte('\n')

	// Render each level. Track whether it's the last node so we can
	// pick └─ instead of ├─ and switch the gutter to spaces.
	n := len(v.Levels)
	hasLeaf := v.LeafAnswer != nil
	for i, lvl := range v.Levels {
		last := i == n-1 && !hasLeaf
		branch := "├─ "
		gutter := "│  "
		if last {
			branch = "└─ "
			gutter = "   "
		}
		zoneLabel := lvl.Zone
		if zoneLabel == "." {
			zoneLabel = ". (root)"
		}
		// First line: branch + zone + KSK info.
		line := branch + zoneLabel
		if lvl.KSKTag != 0 {
			line += fmt.Sprintf("  KSK %d", lvl.KSKTag)
		}
		if lvl.Algorithm != "" {
			line += "  " + lvl.Algorithm
		}
		b.WriteString(line)
		b.WriteByte('\n')

		// Second line: trust verdict.
		verdict := ""
		switch {
		case lvl.Trusted && lvl.Zone == ".":
			verdict = check + " matches IANA trust anchor"
		case lvl.Trusted:
			verdict = check + " DNSKEY signed by parent DS"
		default:
			if lvl.Reason != "" {
				verdict = cross + " " + lvl.Reason
			} else {
				verdict = cross + " not trusted"
			}
		}
		b.WriteString(gutter + verdict)
		b.WriteByte('\n')

		// Third line (optional): ZSK list.
		if len(lvl.ZSKTags) > 0 {
			tags := make([]string, 0, len(lvl.ZSKTags))
			for _, t := range lvl.ZSKTags {
				tags = append(tags, fmt.Sprintf("%d", t))
			}
			b.WriteString(gutter + "ZSKs: " + strings.Join(tags, ", "))
			b.WriteByte('\n')
		}
	}

	// Leaf answer (A/AAAA RRset) as the final └─ branch.
	if hasLeaf {
		la := v.LeafAnswer
		branch := "└─ "
		gutter := "   "
		mark := check
		if !la.Verified {
			mark = cross
		}
		rec := la.Type
		if len(la.Records) > 0 {
			rec += " → " + strings.Join(la.Records, ", ")
		}
		b.WriteString(branch + rec)
		b.WriteByte('\n')
		signedBy := ""
		if la.SignedBy != 0 {
			signedBy = fmt.Sprintf(" signed by ZSK %d", la.SignedBy)
		}
		b.WriteString(gutter + mark + " RRSIG verified" + signedBy)
	}

	// Trim any stray trailing newline so callers can decide what to do next.
	out := b.String()
	return strings.TrimRight(out, "\n")
}
