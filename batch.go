package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Multi-target batch mode. Shifts netdoc from "single-host investigation"
// to "fleet monitoring" — the single biggest feature lever for org-level
// adoption.
//
// Invocation patterns:
//   netdoc -f targets.txt               # newline-delimited file
//   netdoc -f -                         # read targets from stdin
//   netdoc a.com b.com c.com            # multiple positional args
//   netdoc -f targets.txt --json        # one JSON object per line (JSONL)
//   netdoc -f targets.txt --concurrency 16
//
// Output shape:
//   - terminal: per-target summary table + aggregate stats
//   - --json:   newline-delimited JSON (JSONL) — one full Report per line
//
// History: every scan also appends to ~/.netdoc/history.jsonl unless
// --no-history is set. Single append-only file, no DB, no locking
// concerns. Inspect with: jq -c 'select(.target=="github.com")' ~/.netdoc/history.jsonl

// batchConfig bundles the inputs to runBatch.
type batchConfig struct {
	targets     []string
	concurrency int
	jsonOut     bool
	noHistory   bool
	configure   func(d *diagnosis)   // applies global flags (timeout, dns, ports, ecs, profile, check filter) to each target
	out         io.Writer            // terminal/JSON destination
}

// runBatch executes scans across all targets and writes results to out.
// Returns the number of unhealthy targets (caller exits 1 when > 0).
func runBatch(cfg batchConfig) int {
	if cfg.concurrency <= 0 {
		cfg.concurrency = 8
	}
	if cfg.out == nil {
		cfg.out = os.Stdout
	}

	type result struct {
		idx    int
		target string
		report Report
		err    error
	}
	results := make([]result, len(cfg.targets))

	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	for i, t := range cfg.targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			host, port, scheme, err := parseTarget(target)
			if err != nil {
				results[idx] = result{idx: idx, target: target, err: err}
				return
			}
			d := &diagnosis{host: host, port: port, scheme: scheme, timeout: 5 * time.Second}
			if cfg.configure != nil {
				cfg.configure(d)
			}
			rep := runAllChecks(d)
			results[idx] = result{idx: idx, target: target, report: rep}
		}(i, t)
	}
	wg.Wait()

	// History append happens regardless of output mode — the user can
	// always reconstruct the "current" state with the latest line per
	// target. --no-history opts out.
	if !cfg.noHistory {
		for _, r := range results {
			if r.err != nil {
				continue
			}
			_ = appendHistory(r.report)
		}
	}

	unhealthy := 0

	if cfg.jsonOut {
		enc := json.NewEncoder(cfg.out)
		for _, r := range results {
			if r.err != nil {
				_ = enc.Encode(map[string]string{"target": r.target, "error": r.err.Error()})
				unhealthy++
				continue
			}
			if !r.report.Healthy {
				unhealthy++
			}
			_ = enc.Encode(r.report)
		}
		return unhealthy
	}

	// Terminal mode: compact summary table.
	fmt.Fprintln(cfg.out)
	fmt.Fprintf(cfg.out, "  netdoc batch — %d target%s\n", len(cfg.targets), plural(len(cfg.targets)))
	fmt.Fprintln(cfg.out)
	fmt.Fprintf(cfg.out, "  %-40s  %-10s  %-12s  %s\n", "TARGET", "STATUS", "ELAPSED", "FIX FIRST / NOTES")
	fmt.Fprintf(cfg.out, "  %s\n", strings.Repeat("─", 100))
	for _, r := range results {
		target := truncate(r.target, 40)
		if r.err != nil {
			unhealthy++
			fmt.Fprintf(cfg.out, "  %-40s  %-10s  %-12s  %s\n", target, "error", "—", truncate(r.err.Error(), 40))
			continue
		}
		status := "✓ healthy"
		if !r.report.Healthy {
			status = "✗ problems"
			unhealthy++
		}
		fix := r.report.FixFirst
		if fix == "" && r.report.Healthy {
			fix = "—"
		}
		fmt.Fprintf(cfg.out, "  %-40s  %-10s  %-12s  %s\n", target, status, r.report.Elapsed, truncate(fix, 40))
	}
	fmt.Fprintln(cfg.out)
	fmt.Fprintf(cfg.out, "  %d/%d healthy", len(cfg.targets)-unhealthy, len(cfg.targets))
	if unhealthy > 0 {
		fmt.Fprintf(cfg.out, " · %d need attention", unhealthy)
	}
	fmt.Fprintln(cfg.out)
	fmt.Fprintln(cfg.out)
	return unhealthy
}

// readTargetsFile reads newline-delimited targets from a file path. A
// path of "-" reads from stdin. Blank lines and `#`-prefixed comments
// are skipped.
func readTargetsFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var targets []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
