package main

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// checkLatency runs multiple TCP-connect probes against the first reachable
// IPv4 address and reports round-trip statistics: min / avg / max RTT, jitter
// (population stddev), and packet loss percentage.
//
// TCP-connect is used in place of ICMP because (a) it works unprivileged on
// every supported platform, (b) it travels the same path the user's real
// traffic will take, and (c) it is rarely shaped or dropped the way ICMP is.
func (d *diagnosis) checkLatency() Check {
	c := Check{Name: "Latency"}
	if !d.resolved || len(d.okV4) == 0 {
		c.Status = StatusSkip
		c.Summary = "skipped — no reachable IPv4 address"
		return c
	}

	target := d.okV4[0]
	addr := net.JoinHostPort(target.String(), strconv.Itoa(d.port))

	const probes = 5
	const gap = 80 * time.Millisecond
	perProbe := d.timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}

	var rtts []time.Duration
	var fails int

	// Prefer real ICMP echo. If the first probe succeeds we use ICMP for the
	// whole run; if it errors (no support, blocked, no permission) we fall
	// back to TCP-connect timing on the target's open port, which travels
	// the exact path real traffic does.
	method := "ICMP"
	if rtt, err := pingICMP(target, perProbe); err == nil {
		rtts = append(rtts, rtt)
		for i := 1; i < probes; i++ {
			time.Sleep(gap)
			if r, err := pingICMP(target, perProbe); err == nil {
				rtts = append(rtts, r)
			} else {
				fails++
			}
		}
	} else {
		method = fmt.Sprintf("TCP :%d", d.port)
		for i := 0; i < probes; i++ {
			if i > 0 {
				time.Sleep(gap)
			}
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, perProbe)
			el := time.Since(start)
			if err != nil {
				fails++
				continue
			}
			conn.Close()
			rtts = append(rtts, el)
		}
	}

	lossPct := float64(fails) / float64(probes) * 100

	var minD, maxD, avgD time.Duration
	var jitter float64
	if len(rtts) > 0 {
		minD, maxD = rtts[0], rtts[0]
		var sum time.Duration
		for _, r := range rtts {
			sum += r
			if r < minD {
				minD = r
			}
			if r > maxD {
				maxD = r
			}
		}
		avgD = sum / time.Duration(len(rtts))

		avgMs := ms(avgD)
		var sq float64
		for _, r := range rtts {
			diff := ms(r) - avgMs
			sq += diff * diff
		}
		jitter = math.Sqrt(sq / float64(len(rtts)))
	}

	c.Detail = map[string]any{
		"probes":     probes,
		"successful": len(rtts),
		"loss_pct":   lossPct,
		"min_ms":     ms(minD),
		"avg_ms":     ms(avgD),
		"max_ms":     ms(maxD),
		"jitter_ms":  jitter,
		"target_ip":  target.String(),
		"method":     method,
	}
	c.Millis = ms(avgD)

	if len(rtts) > 0 {
		parts := []string{
			fmt.Sprintf("min %s  ·  avg %s  ·  max %s", dur(minD), dur(avgD), dur(maxD)),
			fmt.Sprintf("jitter %.1fms", jitter),
		}
		if lossPct > 0 {
			parts = append(parts, fmt.Sprintf("loss %.0f%%", lossPct))
		}
		c.Hint = strings.Join(parts, "  ·  ")
	}

	switch {
	case len(rtts) == 0:
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("no probes succeeded (%d/%d failed)", fails, probes)
	case lossPct >= 50:
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("%.0f%% packet loss — path heavily degraded", lossPct)
	case lossPct > 0:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%.0f%% packet loss (%d/%d probes failed) — avg %s",
			lossPct, fails, probes, dur(avgD))
	case len(rtts) >= 3 && jitter > ms(avgD)*0.5 && avgD > 5*time.Millisecond:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("high jitter — avg %s  ±  %.1fms", dur(avgD), jitter)
	default:
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("avg %s over %d probes (%s)", dur(avgD), len(rtts), method)
	}
	return c
}
