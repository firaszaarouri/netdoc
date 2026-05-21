package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// checkPath runs an ICMP-based per-hop traceroute to the first reachable
// IPv4 address. Returns ok when the destination responds; warn when the
// path runs to maxHops without reaching it.
func (d *diagnosis) checkPath() Check {
	c := Check{Name: "Path"}
	if !d.resolved || len(d.okV4) == 0 {
		c.Status = StatusSkip
		c.Summary = "skipped — no reachable IPv4 address"
		return c
	}
	target := d.okV4[0]

	// Cheap sanity probe — if ICMP isn't AVAILABLE on this platform
	// (long-tail Unix stub) the probe returns the "not yet implemented"
	// error and we skip entirely. If ICMP IS available but the target
	// firewalls ICMP echo (common on Google Cloud, AWS, some CDNs), we
	// still try the path checks via UDP traceroute (Linux IP_RECVERR) —
	// it often succeeds where ICMP is dropped at the destination.
	icmpAvailable := true
	icmpTargetReachable := true
	if _, _, _, err := pingICMPWithTTL(target, 64, d.timeout); err != nil {
		if strings.Contains(err.Error(), "not yet implemented") {
			icmpAvailable = false
		}
		icmpTargetReachable = false
	}
	if !icmpAvailable {
		c.Status = StatusSkip
		c.Summary = "skipped — ICMP traceroute not available on this platform"
		return c
	}

	const maxHops = 30
	var hops []hopResult
	if icmpTargetReachable {
		hops = traceRoute(target, maxHops, d.timeout)
	}

	// Parallel: ASN annotation + Path-MTU + IPv6 flow-label ECMP probe +
	// IPv4 TCP-source-port ECMP probe + IPv4 UDP traceroute. All five are
	// independent of each other and of the main hop list.
	var (
		mtu      int
		ipv6ECMP flowLabelResult
		tcpECMP  tcpECMPResult
		udpTrace udpTraceResult
	)
	var pWG sync.WaitGroup
	pWG.Add(5)
	go func() {
		defer pWG.Done()
		d.annotateHopsWithASN(hops)
	}()
	go func() {
		defer pWG.Done()
		mtu = detectPathMTU(target, d.timeout)
	}()
	go func() {
		defer pWG.Done()
		// IPv6 flow-label ECMP only when the target has reachable AAAA.
		// Unprivileged on Linux + macOS; the platform stub returns
		// Attempted=false elsewhere.
		if len(d.okV6) > 0 {
			ipv6ECMP = probeIPv6ECMP(d.okV6[0], maxHops, d.timeout)
		}
	}()
	go func() {
		defer pWG.Done()
		// IPv4 TCP-source-port ECMP — Linux only (IP_RECVERR). Dst port
		// 443 since virtually every public network allows outbound 443.
		tcpECMP = probeIPv4ECMPTCP(target, 443, maxHops, d.timeout)
	}()
	go func() {
		defer pWG.Done()
		// IPv4 UDP traceroute — Linux only (IP_RECVERR). Useful as
		// fallback when ICMP echo is filtered at destination, and as
		// secondary path verification when ICMP works.
		udpTrace = probeIPv4UDPTraceroute(target, maxHops, d.timeout)
	}()
	pWG.Wait()

	// Fallback: if ICMP didn't see any hops but UDP did, promote UDP's
	// hop list to the primary report so the user gets actionable path
	// data even when the destination filters ICMP echo.
	icmpHopCount := len(hops)
	usedUDPFallback := false
	if len(hops) == 0 && udpTrace.Attempted && len(udpTrace.Hops) > 0 {
		hops = udpTrace.Hops
		d.annotateHopsWithASN(hops)
		usedUDPFallback = true
	}

	c.Detail = map[string]any{
		"target":    target.String(),
		"hop_count": len(hops),
		"max_hops":  maxHops,
		"hops":      hops,
	}
	if mtu > 0 {
		c.Detail["mtu"] = mtu
	}
	if ipv6ECMP.Attempted {
		c.Detail["ipv6_ecmp"] = ipv6ECMP
	}
	if tcpECMP.Attempted {
		c.Detail["ipv4_ecmp_tcp"] = tcpECMP
	}
	if udpTrace.Attempted {
		c.Detail["ipv4_udp_traceroute"] = udpTrace
	}
	if usedUDPFallback {
		c.Detail["primary_source"] = "udp_traceroute"
	}

	if len(hops) == 0 {
		c.Status = StatusWarn
		if !icmpTargetReachable {
			c.Summary = "no responding hops (ICMP filtered at destination, UDP traceroute also silent)"
		} else {
			c.Summary = "no responding hops"
		}
		return c
	}

	var destReached bool
	var destRTT time.Duration
	for _, h := range hops {
		if h.Reached {
			destReached = true
			destRTT = h.rtt
			break
		}
	}

	if destReached {
		c.Millis = ms(destRTT)
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("%d hop%s to destination in %s", len(hops), plural(len(hops)), dur(destRTT))
	} else {
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("path stopped after %d hops — destination did not respond", len(hops))
	}
	if mtu > 0 {
		c.Summary += fmt.Sprintf(" · MTU %d", mtu)
	}
	if h := tcpECMPHeadline(tcpECMP); h != "" {
		c.Summary += " · " + h
	}
	if h := ecmpHeadline(ipv6ECMP); h != "" {
		c.Summary += " · " + h
	}
	if h := udpTraceHeadline(udpTrace, icmpHopCount); h != "" {
		c.Summary += " · " + h
	}
	if usedUDPFallback {
		c.Summary += " · via UDP (ICMP filtered at destination)"
	}

	// Multi-line hint with one line per hop. The renderer indents each line
	// to the standard hint column.
	var lines []string
	for _, h := range hops {
		if h.IP == "" {
			lines = append(lines, fmt.Sprintf("%2d.  * * *", h.TTL))
			continue
		}
		label := h.Name
		if label == "" {
			label = h.IP
		}
		asn := ""
		if h.ASN != "" {
			asn = "  " + h.ASN
			if h.ASNOrg != "" {
				asn += " · " + truncate(h.ASNOrg, 18)
			}
		}
		// Per-hop metrics: avg ± jitter / loss% when meaningful, else avg.
		metric := dur(h.rtt)
		if h.JitterMs > 0.5 || h.LossPct > 0 {
			metric = fmt.Sprintf("%s ±%.0fms", dur(h.rtt), h.JitterMs)
			if h.LossPct > 0 {
				metric += fmt.Sprintf(" %d%%↓", h.LossPct)
			}
		}
		lines = append(lines, fmt.Sprintf("%2d.  %-32s  %s%s", h.TTL, truncate(label, 30), metric, asn))
	}
	c.Hint = strings.Join(lines, "\n")

	return c
}

// annotateHopsWithASN looks up each hop's IP against Team Cymru's free DNS-
// based IP-to-ASN service and fills in the ASN, org and country fields on
// hopResult. Private addresses are skipped to avoid wasting queries.
func (d *diagnosis) annotateHopsWithASN(hops []hopResult) {
	var wg sync.WaitGroup
	for i := range hops {
		ipStr := hops[i].IP
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || isPrivateIP(ip) {
			continue
		}
		wg.Add(1)
		go func(idx int, ip net.IP) {
			defer wg.Done()
			info, err := lookupASN(ip, d.dnsTransport, time.Second)
			if err != nil || info.ASN == "" {
				return
			}
			hops[idx].ASN = "AS" + info.ASN
			hops[idx].ASNOrg = stripCCFromOrg(info.Org, info.Country)
			hops[idx].ASNCC = info.Country
		}(i, ip)
	}
	wg.Wait()
}
