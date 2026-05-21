package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// JSONL-backed scan history. One record per scan, one line per record,
// append-only. Lives at ~/.netdoc/history.jsonl.
//
// Brand justification: chose JSONL over sqlite to preserve the
// zero-CGO single-static-binary promise. Cross-compiles cleanly. Trivial
// to inspect/grep/jq. Append-only is concurrency-safe on POSIX
// (writes ≤ PIPE_BUF / 4 KiB are atomic) — concurrent netdoc runs from
// batch mode safely interleave records.
//
// Trade-off: linear scan on read. Acceptable for the expected scale
// (single-user fleet of 10-10000 targets, scanned daily, file grows
// ~1 MB/year/target). If file growth becomes a problem, rotate by
// month or cap retained records per target.

// historyRecord is the per-scan envelope written to history.jsonl. We
// embed the timestamp at the top level for cheap grep/jq selection
// without parsing the nested Report.
type historyRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	Healthy   bool      `json:"healthy"`
	FixFirst  string    `json:"fix_first,omitempty"`
	Elapsed   string    `json:"elapsed,omitempty"`
	Report    Report    `json:"report"`
}

// historyPath returns the path to ~/.netdoc/history.jsonl, creating the
// parent directory if needed. Honors $NETDOC_HISTORY override for tests
// and per-tenant separation.
func historyPath() (string, error) {
	if override := os.Getenv("NETDOC_HISTORY"); override != "" {
		if err := os.MkdirAll(filepath.Dir(override), 0o755); err != nil {
			return "", err
		}
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".netdoc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "history.jsonl"), nil
}

// appendHistory writes one scan record to the history file. Errors are
// returned but typically ignored by callers (history is best-effort).
func appendHistory(r Report) error {
	path, err := historyPath()
	if err != nil {
		return err
	}
	rec := historyRecord{
		Timestamp: time.Now().UTC(),
		Target:    r.Target,
		Host:      r.Host,
		Healthy:   r.Healthy,
		FixFirst:  r.FixFirst,
		Elapsed:   r.Elapsed,
		Report:    r,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// readHistory returns the last N records for the given target, oldest
// first. If target is empty, returns N records across all targets.
func readHistory(target string, n int) ([]historyRecord, error) {
	if n <= 0 {
		n = 10
	}
	path, err := historyPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []historyRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		var rec historyRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue // tolerate stray malformed lines
		}
		if target != "" && rec.Host != target && rec.Target != target {
			continue
		}
		all = append(all, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

// renderHistoryTable writes a compact ASCII table summarizing N history
// records to w. Used by `netdoc <target> --history N`.
func renderHistoryTable(w io.Writer, target string, recs []historyRecord) {
	if len(recs) == 0 {
		path, _ := historyPath()
		if path == "" {
			path = "~/.netdoc/history.jsonl"
		}
		fmt.Fprintf(w, "\n  No history for %q. Run a scan to populate %s.\n\n", target, path)
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  netdoc history — %s  (last %d scan%s)\n", target, len(recs), plural(len(recs)))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-22s  %-10s  %-12s  %s\n", "TIMESTAMP", "STATUS", "ELAPSED", "FIX FIRST")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 92))
	for _, r := range recs {
		ts := r.Timestamp.Local().Format("2006-01-02 15:04:05")
		status := "✓ healthy"
		if !r.Healthy {
			status = "✗ problems"
		}
		fix := r.FixFirst
		if fix == "" {
			fix = "—"
		}
		fmt.Fprintf(w, "  %-22s  %-10s  %-12s  %s\n", ts, status, r.Elapsed, truncate(fix, 40))
	}
	fmt.Fprintln(w)
}
