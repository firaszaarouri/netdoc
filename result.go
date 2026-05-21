package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// version is the netdoc semantic-version string surfaced via --version
// and the JSON report header. Declared as var (not const) so the
// GoReleaser build can inject the git-tag value at link time via
// `-ldflags "-X main.version={{.Version}}"`. Untagged go-build defaults
// to whatever this source-of-truth value is.
var version = "1.0.0"

// Status values for a Check.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Check is the result of one diagnostic stage.
type Check struct {
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Summary string         `json:"summary"`
	Hint    string         `json:"hint,omitempty"`
	Millis  float64        `json:"ms,omitempty"` // headline duration, for the timing chart
	Detail  map[string]any `json:"detail,omitempty"`
}

// Report is the full diagnostic result for a target.
type Report struct {
	Target   string   `json:"target"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Scheme   string   `json:"scheme"`
	Healthy  bool     `json:"healthy"`
	Checks   []Check      `json:"checks"`
	Trace    *TraceResult `json:"trace,omitempty"`
	Problems []string     `json:"problems,omitempty"`
	FixFirst string   `json:"fix_first,omitempty"`
	Elapsed  string   `json:"elapsed"`
}

// diagnosis carries shared state across the checks for a single run.
type diagnosis struct {
	host    string
	port    int
	scheme  string
	timeout time.Duration

	resolved bool
	ipv4     []net.IP
	ipv6     []net.IP
	okV4     []net.IP
	okV6     []net.IP

	dnsTransport *dnsTransport // nil means "use the system resolver"; otherwise drives every DNS query
	portsToScan  []int         // populated by --ports; empty means skip the Ports check entirely
	ecsSubnets   []string      // populated by --ecs; empty means skip ECS probes
	trace        *TraceResult  // populated by runTrace; consumed by checkHTTP and the timing chart
	filter       *checkFilter  // populated by --check or --profile; nil means run every check
	starttlsProto startTLSProtocol // populated by --starttls; empty means direct TLS
	cipherPattern string         // populated by --cipher-pattern; empty means show full enum
	dnssecTree   bool          // populated by --dnssec-tree; appends ASCII chain visualizer to DNS hint
	eachCipher   bool          // populated by --each-cipher; enumerates the full IANA cipher catalog
}

// dur formats a duration into a short human string.
func dur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
}

// ms returns a duration as a float count of milliseconds (for JSON detail).
func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// tidyErr renders an error as a clean one-line string, dropping the trailing
// punctuation and whitespace that some standard-library errors carry.
func tidyErr(err error) string {
	return strings.TrimRight(err.Error(), " \t\n:;")
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// previewList joins up to n items with a separator, summarising the remainder.
func previewList(items []string, n int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= n {
		return strings.Join(items, "  ·  ")
	}
	return strings.Join(items[:n], "  ·  ") + fmt.Sprintf("  ·  +%d more", len(items)-n)
}
