package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// --watch mode: re-run every check on a tick, redraw the screen in place,
// keep per-probe history rings so latency sparklines can show trends over
// the session. Hand-rolled ANSI cursor control — no bubbletea dep, keeps
// the binary slim.
//
// Layout per tick:
//   netdoc banner + target + clock
//   one Check line per result (status, summary, hint indented)
//   timing chart from the most recent trace
//   sparklines: per-check latency over last N ticks (when latency is meaningful)
//   exit instruction
//
// Ctrl+C is handled cleanly — we restore the cursor + clear any leftover
// ANSI state before exiting so the user's terminal isn't left in a weird mode.

const (
	ansiClear        = "\033[2J"     // clear entire screen
	ansiHome         = "\033[H"      // cursor to row 1, col 1
	ansiHideCursor   = "\033[?25l"
	ansiShowCursor   = "\033[?25h"
	ansiClearLine    = "\033[2K"     // clear current line
	ansiClearBelow   = "\033[0J"     // clear from cursor to end of screen
	maxSparkSamples  = 30            // ring-buffer depth per metric
)

// sparkBlocks is the unicode block-ladder used to render sparklines, from
// "almost empty" to "almost full". Eight steps is plenty of resolution for
// terminal-width charts.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// watchState carries per-check history across ticks.
type watchState struct {
	mu       sync.Mutex
	latency  []float64 // ring of avg-latency-ms values from the Latency check
	ttfb     []float64 // ring of TTFB values from the trace
	throughput []float64 // ring of body throughput KBps
}

func (s *watchState) record(r Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range r.Checks {
		if c.Name == "Latency" && c.Millis > 0 {
			s.latency = appendRing(s.latency, c.Millis, maxSparkSamples)
		}
	}
	if r.Trace != nil {
		ttfb := r.Trace.TCPPhase + r.Trace.TLSPhase + r.Trace.ServerPhase
		if ttfb > 0 {
			s.ttfb = appendRing(s.ttfb, ttfb, maxSparkSamples)
		}
		if r.Trace.ThroughputKBps > 0 {
			s.throughput = appendRing(s.throughput, r.Trace.ThroughputKBps, maxSparkSamples)
		}
	}
}

func (s *watchState) snapshot() (latency, ttfb, throughput []float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	latency = append([]float64(nil), s.latency...)
	ttfb = append([]float64(nil), s.ttfb...)
	throughput = append([]float64(nil), s.throughput...)
	return
}

// runWatch is the --watch entry point. It re-runs all checks on a fixed
// interval, redraws the report in-place, and exits cleanly on Ctrl+C.
//
// We do NOT clear-and-redraw on a sub-second cadence — the checks themselves
// take 1-5 seconds, so a 5s default interval gives ~zero idle time between
// ticks. The interval is the minimum gap between tick-starts; if a tick
// takes longer than that we just start the next one immediately.
func runWatch(d *diagnosis, interval time.Duration) {
	if interval < time.Second {
		interval = time.Second
	}
	state := &watchState{}

	// Install signal handler so Ctrl+C cleans up.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	stdout := os.Stdout
	fmt.Fprint(stdout, ansiHideCursor)
	defer fmt.Fprint(stdout, ansiShowCursor)

	tickNum := 0
	for {
		tickNum++
		tickStart := time.Now()

		// Each tick uses a fresh diagnosis state so previous runs' resolved
		// IPs / trace don't pollute the next iteration.
		freshD := &diagnosis{
			host: d.host, port: d.port, scheme: d.scheme, timeout: d.timeout,
			dnsTransport: d.dnsTransport, portsToScan: d.portsToScan,
		}
		report := runAllChecks(freshD)
		state.record(report)

		// Redraw screen in place.
		fmt.Fprint(stdout, ansiHome, ansiClearBelow)
		renderTerminal(report)
		renderWatchFooter(stdout, state, tickNum, interval)

		// Sleep until next tick (or exit on Ctrl+C).
		elapsed := time.Since(tickStart)
		wait := interval - elapsed
		if wait < 0 {
			wait = 100 * time.Millisecond
		}
		select {
		case <-sigCh:
			fmt.Fprintln(stdout)
			fmt.Fprint(stdout, ansiShowCursor)
			return
		case <-time.After(wait):
		}
	}
}

// renderWatchFooter draws the sparkline section + the exit instruction.
func renderWatchFooter(out *os.File, s *watchState, tick int, interval time.Duration) {
	lat, ttfb, thru := s.snapshot()
	fmt.Fprintln(out, "  "+col(cGray, "─── live ───"))
	if len(lat) > 0 {
		fmt.Fprintln(out, "  "+col(cBold, padRight("Latency", 10))+" "+col(cCyan, sparklineFromSeries(lat))+
			" "+col(cGray, fmt.Sprintf("%.0fms", lat[len(lat)-1])))
	}
	if len(ttfb) > 0 {
		fmt.Fprintln(out, "  "+col(cBold, padRight("TTFB", 10))+" "+col(cCyan, sparklineFromSeries(ttfb))+
			" "+col(cGray, fmt.Sprintf("%.0fms", ttfb[len(ttfb)-1])))
	}
	if len(thru) > 0 {
		fmt.Fprintln(out, "  "+col(cBold, padRight("Throughput", 10))+" "+col(cCyan, sparklineFromSeries(thru))+
			" "+col(cGray, fmt.Sprintf("%.0f KB/s", thru[len(thru)-1])))
	}
	fmt.Fprintln(out, "  "+col(cGray, fmt.Sprintf("tick #%d   ·   interval %s   ·   Ctrl+C to exit", tick, interval)))
}

// sparklineFromSeries renders a slice of values as a Unicode block sparkline.
// Values are linearly mapped to the 8 block heights between min and max.
func sparklineFromSeries(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	span := maxV - minV
	if span == 0 {
		// All equal — render a flat mid-height bar so the user can still see
		// "yes there's a series here, it's just stable".
		return string(repeatRune(sparkBlocks[3], len(values)))
	}
	out := make([]rune, len(values))
	for i, v := range values {
		idx := int((v - minV) / span * float64(len(sparkBlocks)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkBlocks) {
			idx = len(sparkBlocks) - 1
		}
		out[i] = sparkBlocks[idx]
	}
	return string(out)
}

func repeatRune(r rune, n int) []rune {
	out := make([]rune, n)
	for i := range out {
		out[i] = r
	}
	return out
}

// appendRing adds v to xs, keeping at most maxLen most-recent entries.
func appendRing(xs []float64, v float64, maxLen int) []float64 {
	xs = append(xs, v)
	if len(xs) > maxLen {
		xs = xs[len(xs)-maxLen:]
	}
	return xs
}
