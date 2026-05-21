package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// formatIPLine builds the first DNS hint line: IPs plus ASN annotations.
// When every IP shares the same ASN, the annotation is hoisted to a single
// trailing tag; otherwise each IP gets its own parenthesised label.
func formatIPLine(v4, v6 []net.IP, asns map[string]asnInfo) string {
	all := append([]net.IP{}, v4...)
	all = append(all, v6...)
	if len(all) == 0 {
		return ""
	}
	sharedASN := ""
	allSame := len(asns) > 0
	for _, ip := range all {
		info, ok := asns[ip.String()]
		if !ok || info.ASN == "" {
			allSame = false
			break
		}
		if sharedASN == "" {
			sharedASN = info.ASN
		} else if info.ASN != sharedASN {
			allSame = false
			break
		}
	}
	if allSame {
		labels := make([]string, 0, len(all))
		for _, ip := range all {
			labels = append(labels, ip.String())
		}
		line := previewList(labels, 4)
		for _, info := range asns {
			line += "  ·  " + info.String()
			break
		}
		return line
	}
	labels := make([]string, 0, len(all))
	for _, ip := range all {
		label := ip.String()
		if info, ok := asns[ip.String()]; ok && info.ASN != "" {
			label += " (" + info.String() + ")"
		}
		labels = append(labels, label)
	}
	return previewList(labels, 4)
}

// checkDNS resolves the target host to A and AAAA records.
func (d *diagnosis) checkDNS() Check {
	c := Check{Name: "DNS"}

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	// When --dns selects an explicit transport (udp / tcp / dot / doh), all
	// queries flow through it; otherwise we use Go's pure-Go resolver, which
	// issues real A/AAAA queries (the system resolver on some platforms —
	// notably Windows without IPv6 — silently drops AAAA records).
	start := time.Now()
	var addrs []net.IP
	var err error
	if d.dnsTransport != nil {
		addrs, err = resolveViaTransport(d.host, d.dnsTransport, d.timeout)
	} else {
		resolver := &net.Resolver{PreferGo: true}
		addrs, err = resolver.LookupIP(ctx, "ip", d.host)
		if err != nil {
			addrs, err = net.DefaultResolver.LookupIP(ctx, "ip", d.host)
		}
	}
	elapsed := time.Since(start)

	if err != nil {
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("could not resolve %q", d.host)
		c.Detail = map[string]any{"error": tidyErr(err), "ms": ms(elapsed)}
		return c
	}
	if len(addrs) == 0 {
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("%q has no DNS records", d.host)
		return c
	}

	for _, ip := range addrs {
		if ip.To4() != nil {
			d.ipv4 = append(d.ipv4, ip)
		} else {
			d.ipv6 = append(d.ipv6, ip)
		}
	}
	d.resolved = true

	v4 := make([]string, 0, len(d.ipv4))
	for _, ip := range d.ipv4 {
		v4 = append(v4, ip.String())
	}
	v6 := make([]string, 0, len(d.ipv6))
	for _, ip := range d.ipv6 {
		v6 = append(v6, ip.String())
	}
	c.Detail = map[string]any{"ms": ms(elapsed), "ipv4": v4, "ipv6": v6}
	if d.dnsTransport != nil {
		c.Detail["transport"] = d.dnsTransport.String()
	}
	c.Millis = ms(elapsed)

	// Enrich the DNS detail with other record types in parallel — best-effort,
	// these never fail the check. Results go to JSON detail and the hint lines.
	// enrichDNS also performs per-IP ASN lookups via Team Cymru DNS and is
	// responsible for building c.Hint with ASN-annotated IPs.
	d.enrichDNS(ctx, &c)

	if elapsed > 300*time.Millisecond {
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("slow DNS — resolved in %s (%d IPv4, %d IPv6)", dur(elapsed), len(d.ipv4), len(d.ipv6))
	} else {
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("resolved in %s — %d IPv4, %d IPv6", dur(elapsed), len(d.ipv4), len(d.ipv6))
	}
	return c
}

// enrichDNS performs additional record-type lookups concurrently (MX, NS, TXT,
// CNAME, reverse PTR for the first IPv4) and stuffs the results into the DNS
// check's Detail map and second hint line. Each lookup is best-effort — a
// failure leaves the corresponding key absent rather than failing the check.
func (d *diagnosis) enrichDNS(parent context.Context, c *Check) {
	// Bound the auxiliary lookups tightly so they cannot dominate the run.
	deadline := 2 * time.Second
	if d.timeout < deadline {
		deadline = d.timeout
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}

	var (
		mx, ns, txt, ptr              []string
		srv, caa, httpsRecs, svcbRecs []string
		cname                         string
		sec                           dnssecStatus
		asns                          map[string]asnInfo
		nsid                          string
		mu                            sync.Mutex
	)

	var wg sync.WaitGroup

	add := func(slot *[]string, vals []string) {
		mu.Lock()
		defer mu.Unlock()
		*slot = append(*slot, vals...)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if rs, err := resolver.LookupMX(ctx, d.host); err == nil {
			var out []string
			for _, r := range rs {
				out = append(out, fmt.Sprintf("%s (pref %d)", strings.TrimSuffix(r.Host, "."), r.Pref))
			}
			add(&mx, out)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rs, err := resolver.LookupNS(ctx, d.host); err == nil {
			var out []string
			for _, r := range rs {
				out = append(out, strings.TrimSuffix(r.Host, "."))
			}
			add(&ns, out)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rs, err := resolver.LookupTXT(ctx, d.host); err == nil {
			add(&txt, rs)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if v, err := resolver.LookupCNAME(ctx, d.host); err == nil {
			v = strings.TrimSuffix(v, ".")
			if v != "" && v != d.host {
				mu.Lock()
				cname = v
				mu.Unlock()
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(d.ipv4) == 0 {
			return
		}
		if rs, err := resolver.LookupAddr(ctx, d.ipv4[0].String()); err == nil {
			var out []string
			for _, r := range rs {
				out = append(out, strings.TrimSuffix(r, "."))
			}
			add(&ptr, out)
		}
	}()

	// SRV, CAA, HTTPS, SVCB — record types the Go stdlib resolver does not
	// expose, queried directly via miekg/dns against a public resolver.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rrs, err := queryDNS(d.host, dns.TypeSRV, d.dnsTransport, deadline); err == nil {
			var out []string
			for _, r := range rrs {
				if s, ok := r.(*dns.SRV); ok {
					out = append(out, fmt.Sprintf("%d/%d → %s:%d",
						s.Priority, s.Weight, strings.TrimSuffix(s.Target, "."), s.Port))
				}
			}
			add(&srv, out)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rrs, err := queryDNS(d.host, dns.TypeCAA, d.dnsTransport, deadline); err == nil {
			var out []string
			for _, r := range rrs {
				if c, ok := r.(*dns.CAA); ok {
					out = append(out, fmt.Sprintf("%s \"%s\"", c.Tag, c.Value))
				}
			}
			add(&caa, out)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rrs, err := queryDNS(d.host, dns.TypeHTTPS, d.dnsTransport, deadline); err == nil {
			var out []string
			for _, r := range rrs {
				if h, ok := r.(*dns.HTTPS); ok {
					out = append(out, h.String())
				}
			}
			add(&httpsRecs, out)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rrs, err := queryDNS(d.host, dns.TypeSVCB, d.dnsTransport, deadline); err == nil {
			var out []string
			for _, r := range rrs {
				if s, ok := r.(*dns.SVCB); ok {
					out = append(out, s.String())
				}
			}
			add(&svcbRecs, out)
		}
	}()

	// DNSSEC posture: send an A query with DO bit set and inspect the
	// AD bit + RRSIG presence in the reply.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := checkDNSSECStatus(d.host, d.dnsTransport, deadline)
		mu.Lock()
		sec = s
		mu.Unlock()
	}()

	// ASN per resolved IP via Team Cymru's free DNS service. The lookup is
	// itself a DNS query, so it goes through the configured transport for
	// consistency. Results land in the hint line right next to each IP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ips := append([]net.IP{}, d.ipv4...)
		ips = append(ips, d.ipv6...)
		if len(ips) == 0 {
			return
		}
		m := lookupASNs(ips, d.dnsTransport, deadline)
		mu.Lock()
		asns = m
		mu.Unlock()
	}()

	// EDNS0 NSID — ask the resolver to identify itself. On anycast networks
	// (Cloudflare, Quad9, Google) this reveals which PoP answered. Empty
	// when the resolver doesn't support the option.
	wg.Add(1)
	go func() {
		defer wg.Done()
		id := queryNSID(d.host, d.dnsTransport, deadline)
		if id != "" {
			mu.Lock()
			nsid = id
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Post-NS-lookup probes — these depend on the NS list so they can't run
	// in the initial parallel pool above. They DO run in parallel with each
	// other, behind a second WaitGroup, so the cost is one slow batch not N.
	var nsChaos []nsChaosResult
	var axfrResults []axfrResult
	var glueResults []glueResult
	var propagation propagationVerdict
	var ecsResults []ecsResult

	var lameResults []lameNSResult
	if len(ns) > 0 {
		postTimeout := 2 * time.Second
		if d.timeout < postTimeout {
			postTimeout = d.timeout
		}
		var pwg sync.WaitGroup
		pwg.Add(4)
		go func() { defer pwg.Done(); nsChaos = queryCHAOSAll(ns, postTimeout) }()
		go func() { defer pwg.Done(); axfrResults = probeAXFRAll(d.host, ns, postTimeout) }()
		go func() { defer pwg.Done(); glueResults = checkGlue(d.host, ns, postTimeout) }()
		go func() { defer pwg.Done(); lameResults = checkLameDelegation(d.host, ns, postTimeout) }()
		pwg.Wait()
	}

	// DNS Cookies probe runs independently.
	cookies := probeDNSCookies(d.host, d.dnsTransport, 1500*time.Millisecond)

	// NSEC zone-walking (security finding when zone exposes contents).
	var nsecWalk nsecWalkResult
	if sec.Signed {
		nsecWalk = walkZoneNSEC(d.host, d.dnsTransport, 1500*time.Millisecond)
	}

	// RPKI per-prefix via Team Cymru DNS — needs the ASN map.
	rpki := probeRPKIAll(append(append([]net.IP{}, d.ipv4...), d.ipv6...), asns, d.dnsTransport, 1500*time.Millisecond)

	// Multi-resolver propagation view runs in parallel with the above
	// post-NS work but doesn't depend on NS list — it queries public
	// recursors directly. Kicks off here so timing overlaps.
	{
		propTimeout := 2500 * time.Millisecond
		if d.timeout < propTimeout {
			propTimeout = d.timeout
		}
		propagation = probePropagation(d.host, propTimeout)
	}

	// NSEC3 denial-of-existence proof — DNSViz parity. Only meaningful if
	// the zone is signed; runs always because we filter inside probeNSEC3Proof.
	var nsec3Proof nsec3ProofResult
	if sec.Signed || sec.Validated {
		nsec3Proof = probeNSEC3Proof(d.host, d.dnsTransport, d.timeout)
		if nsec3Proof.Attempted {
			c.Detail["nsec3"] = nsec3Proof
		}
	}

	// EDNS Client-Subnet probes — only run when the user passed --ecs.
	if len(d.ecsSubnets) > 0 {
		ecsTimeout := 1500 * time.Millisecond
		if d.timeout < ecsTimeout {
			ecsTimeout = d.timeout
		}
		ecsResults = probeECSMultiple(d.host, d.ecsSubnets, ecsTimeout)
	}

	if len(mx) > 0 {
		c.Detail["mx"] = mx
	}
	if len(ns) > 0 {
		c.Detail["ns"] = ns
	}
	if len(nsChaos) > 0 {
		c.Detail["ns_chaos"] = nsChaos
	}
	if len(axfrResults) > 0 {
		c.Detail["axfr"] = axfrResults
	}
	if len(glueResults) > 0 {
		c.Detail["glue"] = glueResults
	}
	if propagation.ResolversTotal > 0 {
		c.Detail["propagation"] = propagation
	}
	if len(ecsResults) > 0 {
		c.Detail["ecs"] = ecsResults
	}
	if len(lameResults) > 0 {
		c.Detail["lame_delegation"] = lameResults
	}
	if cookies.Supported {
		c.Detail["dns_cookies"] = cookies
	}
	if nsecWalk.ZoneUsesNSEC {
		c.Detail["nsec_walk"] = nsecWalk
	}
	if rpki.Attempted && len(rpki.Statuses) > 0 {
		c.Detail["rpki"] = rpki
	}

	// DNSSEC algorithm-rollover via explicit DNSKEY query.
	var rollover rolloverResult
	if sec.Signed {
		dnskeys := queryDNSKEYSet(d.host, d.dnsTransport, 1500*time.Millisecond)
		if len(dnskeys) > 0 {
			rollover = analyzeDNSKEYRollover(dnskeys)
			if rollover.InProgress {
				c.Detail["algorithm_rollover"] = rollover
			}
		}
	}
	if len(txt) > 0 {
		c.Detail["txt"] = txt
	}
	if cname != "" {
		c.Detail["cname"] = cname
	}
	if len(ptr) > 0 {
		c.Detail["ptr"] = ptr
	}
	if len(srv) > 0 {
		c.Detail["srv"] = srv
	}
	if len(caa) > 0 {
		c.Detail["caa"] = caa
	}
	if len(httpsRecs) > 0 {
		c.Detail["https"] = httpsRecs
	}
	if len(svcbRecs) > 0 {
		c.Detail["svcb"] = svcbRecs
	}
	if sec.Signed || sec.Validated {
		c.Detail["dnssec"] = sec
	}
	if len(asns) > 0 {
		c.Detail["asn"] = asns
	}
	if nsid != "" {
		c.Detail["nsid"] = nsid
	}

	// First hint line: resolved IPs annotated with ASN labels when available.
	// When every IP shares the same ASN (the common Cloudflare/Fastly/Akamai
	// case), the annotation is hoisted to a single trailing tag instead of
	// being repeated per IP — keeps the line compact when fronted by a CDN.
	c.Hint = formatIPLine(d.ipv4, d.ipv6, asns)

	// Second hint line: record types and DNSSEC posture summary.
	var extras []string
	if cname != "" {
		extras = append(extras, "CNAME → "+truncate(cname, 28))
	}
	if len(mx) > 0 {
		extras = append(extras, fmt.Sprintf("MX×%d", len(mx)))
	}
	if len(ns) > 0 {
		extras = append(extras, fmt.Sprintf("NS×%d", len(ns)))
	}
	if len(txt) > 0 {
		extras = append(extras, fmt.Sprintf("TXT×%d", len(txt)))
	}
	if len(caa) > 0 {
		extras = append(extras, fmt.Sprintf("CAA×%d", len(caa)))
	}
	if len(srv) > 0 {
		extras = append(extras, fmt.Sprintf("SRV×%d", len(srv)))
	}
	if len(httpsRecs) > 0 {
		extras = append(extras, "HTTPS")
	}
	if len(svcbRecs) > 0 {
		extras = append(extras, "SVCB")
	}
	switch {
	case sec.ChainValidated:
		// Surface the algorithm + per-zone summary so users see HOW the chain
		// validated (RSASHA256 root, ECDSAP256SHA256 TLD, etc.) — the DNSViz
		// equivalent information without the visualisation.
		label := "DNSSEC: chain-validated"
		if sec.Chain != nil {
			var algs []string
			seen := map[string]bool{}
			for _, lv := range sec.Chain.Levels {
				if lv.Algorithm != "" && !seen[lv.Algorithm] {
					seen[lv.Algorithm] = true
					algs = append(algs, lv.Algorithm)
				}
			}
			if len(algs) > 0 {
				label += " (" + strings.Join(algs, ", ") + ")"
			}
		}
		extras = append(extras, label)
	case sec.Validated:
		extras = append(extras, "DNSSEC: validated (AD bit)")
	case sec.Signed:
		extras = append(extras, "DNSSEC: signed")
	}
	if len(ptr) > 0 {
		extras = append(extras, "rDNS: "+truncate(ptr[0], 28))
	}
	if v := chaosHeadline(nsChaos); v != "" {
		extras = append(extras, "NS: "+truncate(v, 32))
	}
	if v := propagationHeadline(propagation); v != "" {
		extras = append(extras, "propagation: "+v)
	}
	if v := axfrHeadline(axfrResults); v != "" {
		extras = append(extras, v)
	}
	if v := glueHeadline(glueResults); v != "" {
		extras = append(extras, v)
	}
	if v := ecsHeadline(ecsResults); v != "" {
		extras = append(extras, v)
	}
	if v := nsec3Headline(nsec3Proof); v != "" {
		extras = append(extras, v)
	}
	if v := lameDelegationHeadline(lameResults); v != "" {
		extras = append(extras, v)
	}
	if v := dnsCookiesHeadline(cookies); v != "" {
		extras = append(extras, v)
	}
	if v := nsecWalkHeadline(nsecWalk); v != "" {
		extras = append(extras, v)
	}
	if v := rpkiHeadline(rpki); v != "" {
		extras = append(extras, v)
	}
	if v := rolloverHeadline(rollover); v != "" {
		extras = append(extras, v)
	}
	if nsid != "" {
		extras = append(extras, "via "+truncate(nsid, 20))
	}
	if len(extras) > 0 {
		if c.Hint != "" {
			c.Hint += "\n"
		}
		c.Hint += strings.Join(extras, "  ·  ")
	}

	// --dnssec-tree: append the ASCII chain visualizer.
	if d.dnssecTree && sec.Chain != nil {
		tree := renderDNSSECChain(sec.Chain, d.host, useColor)
		if tree != "" {
			if c.Hint != "" {
				c.Hint += "\n\n"
			}
			c.Hint += tree
		}
	}
}
