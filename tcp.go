package main

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// checkTCP attempts a TCP connection to every resolved IP, so a single
// dead address behind a healthy DNS record is caught.
func (d *diagnosis) checkTCP() Check {
	c := Check{Name: "TCP"}

	all := make([]net.IP, 0, len(d.ipv4)+len(d.ipv6))
	all = append(all, d.ipv4...)
	all = append(all, d.ipv6...)
	if len(all) == 0 {
		c.Status = StatusSkip
		c.Summary = "skipped — no addresses to connect to"
		return c
	}

	type result struct {
		IP  string  `json:"ip"`
		OK  bool    `json:"ok"`
		MS  float64 `json:"ms,omitempty"`
		Err string  `json:"error,omitempty"`
	}
	var results []result
	var v4ok, v6ok int
	v4fastest := time.Duration(-1)
	v6fastest := time.Duration(-1)

	for _, ip := range all {
		isV4 := ip.To4() != nil
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(d.port))
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, d.timeout)
		el := time.Since(start)
		if err != nil {
			results = append(results, result{IP: ip.String(), OK: false, Err: tidyErr(err)})
			continue
		}
		conn.Close()
		results = append(results, result{IP: ip.String(), OK: true, MS: ms(el)})
		if isV4 {
			v4ok++
			if v4fastest < 0 || el < v4fastest {
				v4fastest = el
			}
			d.okV4 = append(d.okV4, ip)
		} else {
			v6ok++
			if v6fastest < 0 || el < v6fastest {
				v6fastest = el
			}
			d.okV6 = append(d.okV6, ip)
		}
	}

	c.Detail = map[string]any{"port": d.port, "results": results}

	reachable := make([]string, 0, len(d.okV4)+len(d.okV6))
	for _, ip := range d.okV4 {
		reachable = append(reachable, ip.String())
	}
	for _, ip := range d.okV6 {
		reachable = append(reachable, ip.String())
	}
	c.Hint = previewList(reachable, 4)

	if v4fastest >= 0 {
		c.Millis = ms(v4fastest)
	} else if v6fastest >= 0 {
		c.Millis = ms(v6fastest)
	}

	v4total, v6total := len(d.ipv4), len(d.ipv6)

	// The TCP verdict is judged on IPv4 — the path every client has. IPv6
	// reachability is reported separately by the IPv6 check, so a target is
	// never penalised here for the local machine lacking IPv6.
	if v4total > 0 {
		switch {
		case v4ok == 0:
			c.Status = StatusFail
			c.Summary = fmt.Sprintf("could not connect to any of %d IPv4 address%s on port %d", v4total, plural(v4total), d.port)
		case v4ok < v4total:
			c.Status = StatusWarn
			c.Summary = fmt.Sprintf("%d of %d IPv4 addresses unreachable on port %d — fastest %s",
				v4total-v4ok, v4total, d.port, dur(v4fastest))
		default:
			c.Status = StatusOK
			c.Summary = fmt.Sprintf("connected over IPv4 (%d/%d) on port %d — fastest %s",
				v4ok, v4total, d.port, dur(v4fastest))
		}
		return c
	}

	// IPv6-only host (no A record).
	switch {
	case v6ok == 0:
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("IPv6-only host — could not connect to any of %d address%s on port %d", v6total, plural(v6total), d.port)
	case v6ok < v6total:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("IPv6-only host — %d of %d addresses unreachable on port %d", v6total-v6ok, v6total, d.port)
	default:
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("connected over IPv6 (%d/%d) on port %d — fastest %s", v6ok, v6total, d.port, dur(v6fastest))
	}
	return c
}

// localIPv6Works probes whether the local network has working IPv6 at all
// so an IPv6 failure can be blamed on the right side. The two probes run
// in parallel and the function returns as soon as either one connects.
func localIPv6Works(timeout time.Duration) bool {
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	probes := []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}
	results := make(chan bool, len(probes))
	for _, p := range probes {
		go func(addr string) {
			conn, err := net.DialTimeout("tcp6", addr, timeout)
			if err == nil {
				conn.Close()
				results <- true
				return
			}
			results <- false
		}(p)
	}
	for i := 0; i < len(probes); i++ {
		if <-results {
			return true
		}
	}
	return false
}
