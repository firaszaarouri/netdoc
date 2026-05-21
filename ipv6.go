package main

import "fmt"

// checkIPv6 derives an IPv6 verdict from the DNS and TCP results. When an
// AAAA record exists but no IPv6 connection succeeded, it probes the local
// network to decide whether the host or the local link is at fault.
func (d *diagnosis) checkIPv6() Check {
	c := Check{Name: "IPv6"}
	c.Detail = map[string]any{
		"aaaa_count": len(d.ipv6),
		"connected":  len(d.okV6) > 0,
	}

	switch {
	case len(d.ipv6) == 0:
		c.Status = StatusSkip
		c.Summary = "no IPv6 — host has no AAAA record"
	case len(d.okV6) > 0:
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("reachable over IPv6 (%d AAAA record%s)", len(d.ipv6), plural(len(d.ipv6)))
		v6 := make([]string, 0, len(d.okV6))
		for _, ip := range d.okV6 {
			v6 = append(v6, ip.String())
		}
		c.Hint = previewList(v6, 3)
	case localIPv6Works(d.timeout):
		c.Status = StatusFail
		c.Summary = "AAAA record exists but the host refuses IPv6 connections — black-holing IPv6 users"
	default:
		c.Status = StatusSkip
		c.Summary = "IPv6 not tested — this machine has no IPv6 connectivity"
	}
	return c
}
