package main

import (
	"fmt"
	"os"
	"strings"
)

// ANSI escape codes.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)

const reportWidth = 60

// col wraps a string in an ANSI color when color output is enabled.
func col(color, s string) string {
	if !useColor {
		return s
	}
	return color + s + cReset
}

// statusGlyph returns the symbol and color for a check status.
func statusGlyph(status string) (glyph, color string) {
	switch status {
	case StatusOK:
		return "✓", cGreen
	case StatusWarn:
		return "!", cYellow
	case StatusFail:
		return "✗", cRed
	default:
		return "·", cGray
	}
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// renderTiming draws a small bar chart of the per-phase timings from a
// single HTTP transaction (DNS, TCP, TLS handshake, server processing).
// Phases come from one trace, so they never double-count one another.
func renderTiming(out *os.File, t *TraceResult) {
	if t == nil {
		return
	}
	type bar struct {
		name string
		ms   float64
	}
	bars := []bar{
		{"DNS", t.DNSPhase},
		{"TCP", t.TCPPhase},
		{"TLS", t.TLSPhase},
		{"Server", t.ServerPhase},
	}

	var maxMs float64
	for _, b := range bars {
		if b.ms > maxMs {
			maxMs = b.ms
		}
	}
	if maxMs <= 0 {
		return
	}

	const maxBarWidth = 30
	fmt.Fprintln(out, "  "+col(cGray, "timing  ·  one transaction"))
	for _, b := range bars {
		if b.ms <= 0 {
			continue
		}
		w := int(b.ms / maxMs * maxBarWidth)
		if w < 1 {
			w = 1
		}
		fmt.Fprintf(out, "  %s  %s %s\n",
			col(cBold, padRight(b.name, 6)),
			col(cCyan, strings.Repeat("█", w)),
			col(cGray, fmt.Sprintf("%.0fms", b.ms)),
		)
	}
	if t.TotalPhase > 0 {
		// 8 leading spaces aligns "total" with the bar column (after "  " + 6-wide name + "  ").
		fmt.Fprintln(out, "  "+col(cGray, fmt.Sprintf("        total %.0fms", t.TotalPhase)))
	}
	fmt.Fprintln(out)
}

// renderTerminal prints the human-readable diagnostic report.
func renderTerminal(r Report) {
	out := os.Stdout
	divider := col(cGray, strings.Repeat("─", reportWidth))
	const hintIndent = "              " // 14 spaces — aligns under the summary text (name column = 7)

	fmt.Fprintln(out)
	renderBanner(runInfo(r.Host))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+divider)
	fmt.Fprintln(out)

	for _, c := range r.Checks {
		glyph, color := statusGlyph(c.Status)
		fmt.Fprintf(out, "  %s  %s  %s\n",
			col(color, glyph),
			col(cBold, padRight(c.Name, 7)),
			c.Summary,
		)
		if c.Hint != "" {
			for _, line := range strings.Split(c.Hint, "\n") {
				fmt.Fprintln(out, hintIndent+col(cGray, line))
			}
		}
		fmt.Fprintln(out)
	}

	renderTiming(out, r.Trace)

	fmt.Fprintln(out, "  "+divider)

	stats := fmt.Sprintf("%d checks  ·  %d problem%s  ·  %s",
		len(r.Checks), len(r.Problems), plural(len(r.Problems)), r.Elapsed)

	if r.Healthy {
		fmt.Fprintln(out, "  "+col(cGreen, col(cBold, "✓  Healthy"))+"   "+col(cGray, stats))
	} else {
		fmt.Fprintln(out, "  "+col(cRed, col(cBold, "✗  Problems found"))+"   "+col(cGray, stats))
		if r.FixFirst != "" {
			fmt.Fprintln(out, "  "+col(cYellow, "→ Fix first")+"   "+r.FixFirst)
		}
	}
	fmt.Fprintln(out)
}
