package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Mail-deliverability audit — the SPF + DKIM + DMARC + MTA-STS + TLS-RPT
// pentagon that MXToolbox / Hardenize / internet.nl test on every domain.
// Folded into a single Mail check so users get one verdict on whether their
// domain's email-sending posture is sound.
//
// Heavy reliance on the existing dnsTransport + dnsExchange machinery — every
// probe is a DNS TXT lookup at a well-known label except the MTA-STS policy
// which is an HTTPS GET. All probes run concurrently and tolerate missing
// records gracefully (no record = "not configured", not "broken").

// --- SPF ----------------------------------------------------------------

// spfPolicy describes the SPF record parsed at the domain apex (TXT
// starting with "v=spf1"). Lookups counts the DNS-causing mechanisms
// against RFC 7208 §4.6.4's limit of 10.
type spfPolicy struct {
	Raw       string   `json:"raw"`
	Mechanisms []string `json:"mechanisms,omitempty"`
	All       string   `json:"all,omitempty"` // "-all" / "~all" / "?all" / "+all"
	Lookups   int      `json:"lookups"`
	Issues    []string `json:"issues,omitempty"`
}

// parseSPF parses an SPF record. Only the apex record is inspected here —
// we don't recurse into include: mechanisms to enforce the 10-lookup limit
// transitively; we count the local mechanisms that WOULD cause lookups so
// the user sees the warning even before recursion.
func parseSPF(txt string) *spfPolicy {
	s := strings.TrimSpace(txt)
	if !strings.HasPrefix(strings.ToLower(s), "v=spf1") {
		return nil
	}
	p := &spfPolicy{Raw: s}
	tokens := strings.Fields(s)[1:] // skip "v=spf1"
	for _, t := range tokens {
		tl := strings.ToLower(t)
		p.Mechanisms = append(p.Mechanisms, t)
		switch {
		case tl == "-all", tl == "~all", tl == "?all", tl == "+all":
			p.All = tl
		case strings.HasPrefix(tl, "a"), strings.HasPrefix(tl, "mx"),
			strings.HasPrefix(tl, "include:"), strings.HasPrefix(tl, "exists:"),
			strings.HasPrefix(tl, "ptr"):
			p.Lookups++
		}
	}
	if p.All == "" {
		p.Issues = append(p.Issues, "no terminal 'all' mechanism")
	}
	if p.All == "+all" {
		p.Issues = append(p.Issues, "+all permits anyone — equivalent to no SPF")
	}
	if p.Lookups > 10 {
		p.Issues = append(p.Issues, fmt.Sprintf("%d lookup-causing mechanisms (RFC 7208 max 10)", p.Lookups))
	}
	return p
}

// --- DMARC --------------------------------------------------------------

type dmarcPolicy struct {
	Raw         string   `json:"raw"`
	Version     string   `json:"version,omitempty"`
	Policy      string   `json:"policy,omitempty"`     // "none" / "quarantine" / "reject"
	SubPolicy   string   `json:"subdomain_policy,omitempty"`
	Percentage  int      `json:"percentage,omitempty"`
	RUA         []string `json:"rua,omitempty"`
	RUF         []string `json:"ruf,omitempty"`
	AlignDKIM   string   `json:"alignment_dkim,omitempty"`
	AlignSPF    string   `json:"alignment_spf,omitempty"`
	Issues      []string `json:"issues,omitempty"`
}

// parseDMARC parses a DMARC record (TXT at _dmarc.<domain> starting with
// "v=DMARC1"). Untouched fields stay zero; missing required fields surface
// as Issues.
func parseDMARC(txt string) *dmarcPolicy {
	s := strings.TrimSpace(txt)
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "v=dmarc1") {
		return nil
	}
	p := &dmarcPolicy{Raw: s, Percentage: 100}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		switch key {
		case "v":
			p.Version = val
		case "p":
			p.Policy = strings.ToLower(val)
		case "sp":
			p.SubPolicy = strings.ToLower(val)
		case "pct":
			if n, err := strconv.Atoi(val); err == nil {
				p.Percentage = n
			}
		case "rua":
			p.RUA = splitDMARCAddrs(val)
		case "ruf":
			p.RUF = splitDMARCAddrs(val)
		case "adkim":
			p.AlignDKIM = strings.ToLower(val)
		case "aspf":
			p.AlignSPF = strings.ToLower(val)
		}
	}
	if p.Policy == "" {
		p.Issues = append(p.Issues, "no p= directive")
	}
	if p.Policy == "none" {
		p.Issues = append(p.Issues, "p=none — monitoring mode, not enforced")
	}
	if len(p.RUA) == 0 && len(p.RUF) == 0 {
		p.Issues = append(p.Issues, "no rua/ruf reporting endpoints")
	}
	if p.Percentage < 100 {
		p.Issues = append(p.Issues, fmt.Sprintf("pct=%d — partial enforcement", p.Percentage))
	}
	return p
}

func splitDMARCAddrs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// --- DKIM (selector probe) ----------------------------------------------

// commonDKIMSelectors covers the bulk of real-world deployments. We probe
// each in parallel and surface whichever return a key. Comprehensive
// enumeration would need access to actual signed mail; this is best-effort.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2",
	"dkim", "mail", "mta1", "mta2", "smtp", "s1", "s2",
}

type dkimSelector struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Key     string `json:"key,omitempty"`     // trimmed
	KeyType string `json:"key_type,omitempty"` // rsa / ed25519
}

func probeDKIMSelectors(domain string, transport *dnsTransport, timeout time.Duration) []dkimSelector {
	var found []dkimSelector
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sel := range commonDKIMSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			q := sel + "._domainkey." + domain
			rrs, err := queryDNS(q, dns.TypeTXT, transport, timeout)
			if err != nil || len(rrs) == 0 {
				return
			}
			for _, rr := range rrs {
				t, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}
				joined := strings.Join(t.Txt, "")
				if !strings.Contains(strings.ToLower(joined), "v=dkim1") &&
					!strings.Contains(strings.ToLower(joined), "k=") &&
					!strings.Contains(strings.ToLower(joined), "p=") {
					continue
				}
				e := dkimSelector{Name: sel, Found: true, Key: truncate(joined, 80)}
				low := strings.ToLower(joined)
				switch {
				case strings.Contains(low, "k=ed25519"):
					e.KeyType = "ed25519"
				case strings.Contains(low, "k=rsa"):
					e.KeyType = "rsa"
				default:
					e.KeyType = "rsa" // RFC 6376 default
				}
				mu.Lock()
				found = append(found, e)
				mu.Unlock()
				return
			}
		}(sel)
	}
	wg.Wait()
	return found
}

// --- MTA-STS ------------------------------------------------------------

type mtaSTS struct {
	DNSPresent      bool     `json:"dns_present"`
	DNSValue        string   `json:"dns_value,omitempty"`
	PolicyPresent   bool     `json:"policy_present"`
	Mode            string   `json:"mode,omitempty"` // "enforce" / "testing" / "none"
	MaxAge          int      `json:"max_age,omitempty"`
	MXPatterns      []string `json:"mx_patterns,omitempty"`
	Issues          []string `json:"issues,omitempty"`
}

// probeMTASTS first checks the _mta-sts.<domain> TXT record, then fetches
// the HTTPS policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.
// Both must be present; mode=enforce is the strict configuration.
func probeMTASTS(domain string, transport *dnsTransport, timeout time.Duration) *mtaSTS {
	out := &mtaSTS{}
	rrs, _ := queryDNS("_mta-sts."+domain, dns.TypeTXT, transport, timeout)
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			joined := strings.Join(t.Txt, "")
			if strings.Contains(strings.ToLower(joined), "v=stsv1") {
				out.DNSPresent = true
				out.DNSValue = joined
			}
		}
	}
	if !out.DNSPresent {
		return out
	}

	policyURL := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: "mta-sts." + domain},
		},
	}
	resp, err := client.Get(policyURL)
	if err != nil {
		out.Issues = append(out.Issues, "policy fetch failed: "+tidyErr(err))
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out.Issues = append(out.Issues, fmt.Sprintf("policy HTTP %d", resp.StatusCode))
		return out
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	out.PolicyPresent = true
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "mode":
			out.Mode = strings.ToLower(v)
		case "max_age":
			if n, err := strconv.Atoi(v); err == nil {
				out.MaxAge = n
			}
		case "mx":
			out.MXPatterns = append(out.MXPatterns, v)
		}
	}
	if out.Mode == "none" {
		out.Issues = append(out.Issues, "mode=none — policy advertised but not enforced")
	}
	if out.Mode == "testing" {
		out.Issues = append(out.Issues, "mode=testing — failures reported but not blocked")
	}
	return out
}

// --- TLS-RPT ------------------------------------------------------------

type tlsRPT struct {
	Present bool   `json:"present"`
	Raw     string `json:"raw,omitempty"`
	Report  string `json:"report,omitempty"` // rua endpoint
}

func probeTLSRPT(domain string, transport *dnsTransport, timeout time.Duration) *tlsRPT {
	out := &tlsRPT{}
	rrs, _ := queryDNS("_smtp._tls."+domain, dns.TypeTXT, transport, timeout)
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			joined := strings.Join(t.Txt, "")
			if strings.Contains(strings.ToLower(joined), "v=tlsrptv1") {
				out.Present = true
				out.Raw = joined
				for _, part := range strings.Split(joined, ";") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(strings.ToLower(part), "rua=") {
						out.Report = strings.TrimSpace(part[4:])
					}
				}
			}
		}
	}
	return out
}

// --- Apex SPF probe (helper around queryDNS) ----------------------------

func probeSPF(domain string, transport *dnsTransport, timeout time.Duration) *spfPolicy {
	rrs, _ := queryDNS(domain, dns.TypeTXT, transport, timeout)
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			joined := strings.Join(t.Txt, "")
			if p := parseSPF(joined); p != nil {
				return p
			}
		}
	}
	return nil
}

func probeDMARC(domain string, transport *dnsTransport, timeout time.Duration) *dmarcPolicy {
	rrs, _ := queryDNS("_dmarc."+domain, dns.TypeTXT, transport, timeout)
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			joined := strings.Join(t.Txt, "")
			if p := parseDMARC(joined); p != nil {
				return p
			}
		}
	}
	return nil
}

// --- Check integration --------------------------------------------------

// checkMail runs the full mail-deliverability audit concurrently and
// summarises the findings. Skipped when the target has no MX records
// (no mail infrastructure to audit).
func (d *diagnosis) checkMail() Check {
	c := Check{Name: "Mail"}
	if !d.resolved {
		c.Status = StatusSkip
		c.Summary = "skipped — DNS did not resolve"
		return c
	}
	domain := d.host
	// Skip for IP literals.
	if isIPLiteral(domain) {
		c.Status = StatusSkip
		c.Summary = "skipped — IP literal target"
		return c
	}

	// First: do we have MX records? If not, this domain doesn't accept mail.
	mxRRs, _ := queryDNS(domain, dns.TypeMX, d.dnsTransport, d.timeout)
	hasMX := false
	for _, rr := range mxRRs {
		if _, ok := rr.(*dns.MX); ok {
			hasMX = true
			break
		}
	}
	if !hasMX {
		c.Status = StatusSkip
		c.Summary = "skipped — no MX records (domain does not receive mail)"
		return c
	}

	// Build the MX host list once — used by IPv6-MX, DANE-MX, and the
	// existing STARTTLS probe.
	var mxHosts []string
	for _, rr := range mxRRs {
		if mx, ok := rr.(*dns.MX); ok {
			mxHosts = append(mxHosts, strings.TrimSuffix(mx.Mx, "."))
		}
	}

	// Parallel probes — all the mail-posture records live at different labels.
	var spf *spfPolicy
	var dmarc *dmarcPolicy
	var sts *mtaSTS
	var rpt *tlsRPT
	var dkim []dkimSelector
	var mxTLS []mxSTARTTLSResult
	var bimi bimiRecord
	var mxDANE []mxDANEResult
	var mxV6 []mxIPv6Result
	var wg sync.WaitGroup
	wg.Add(9)
	go func() { defer wg.Done(); spf = probeSPF(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); dmarc = probeDMARC(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); sts = probeMTASTS(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); rpt = probeTLSRPT(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); dkim = probeDKIMSelectors(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); mxTLS = probeSTARTTLSForDomain(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); bimi = probeBIMI(domain, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); mxDANE = probeMXDANE(mxHosts, d.dnsTransport, d.timeout) }()
	go func() { defer wg.Done(); mxV6 = probeMXIPv6(mxHosts, d.dnsTransport, d.timeout) }()
	wg.Wait()

	// DKIM key strength — sequential after probeDKIMSelectors completes since
	// it queries each found selector's TXT for the key bytes.
	dkimKeys := probeDKIMKeyStrength(domain, dkim, d.dnsTransport, d.timeout)

	// Scoring across 7 dimensions (sum to 100). See
	// docs/MAIL_SCORING.md for the rubric.
	//   SPF terminal -all   = 20 pts; ~all = 12; missing = 0
	//   DMARC p=reject      = 20; quarantine = 12; none = 5; missing = 0
	//   DKIM strong key     = 15 (any selector with strong key); weak = 5
	//   MTA-STS enforce     = 15; testing = 8; missing = 0
	//   TLS-RPT present     = 10
	//   DANE-MX SMTP-compliant = 10 (≥1 MX with usage 2 or 3)
	//   IPv6-MX present     = 10 (≥1 MX with AAAA record)
	score := 0
	if spf != nil {
		switch spf.All {
		case "-all":
			score += 20
		case "~all":
			score += 12
		}
	}
	if dmarc != nil {
		switch dmarc.Policy {
		case "reject":
			score += 20
		case "quarantine":
			score += 12
		case "none":
			score += 5
		}
	}
	// DKIM: prefer strong-key signal over mere presence per the 2024
	// internet.nl rubric.
	if len(dkim) > 0 {
		dkimStrong := false
		for _, k := range dkimKeys {
			if k.Strong {
				dkimStrong = true
				break
			}
		}
		if dkimStrong {
			score += 15
		} else {
			score += 5
		}
	}
	if sts != nil && sts.PolicyPresent {
		switch sts.Mode {
		case "enforce":
			score += 15
		case "testing":
			score += 8
		}
	}
	if rpt != nil && rpt.Present {
		score += 10
	}
	// DANE-MX (RFC 7672) — ≥1 MX advertising a TLSA record with cert usage
	// 2 (DANE-TA) or 3 (DANE-EE).
	for _, m := range mxDANE {
		if m.SMTPCompliant {
			score += 10
			break
		}
	}
	// IPv6-MX — ≥1 MX with an AAAA record.
	for _, m := range mxV6 {
		if m.HasAAAA {
			score += 10
			break
		}
	}
	// MX STARTTLS — at least 1 MX advertising + upgrading STARTTLS counts.
	// This is mandatory in internet.nl's mail rating; we treat it as a
	// separate dimension without changing the headline score so existing
	// graders' weights stay calibrated.
	starttlsOK := 0
	for _, m := range mxTLS {
		if m.UpgradeSucceeded {
			starttlsOK++
		}
	}
	grade := scoreToGrade(score)

	c.Detail = map[string]any{
		"score":          score,
		"grade":          grade,
		"spf":            spf,
		"dmarc":          dmarc,
		"dkim":           dkim,
		"dkim_keys":      dkimKeys,
		"mtasts":         sts,
		"tlsrpt":         rpt,
		"mx_starttls":    mxTLS,
		"mx_starttls_ok": starttlsOK,
		"mx_dane":        mxDANE,
		"mx_ipv6":        mxV6,
	}
	if bimi.Found {
		c.Detail["bimi"] = bimi
	}
	// DMARC external destination authorization (RFC 7489 §7.1) — collected
	// here, surfaced in the hint line below.
	var dmarcExtAuthHeadline string
	if dmarc != nil {
		endpoints := append([]string{}, dmarc.RUA...)
		endpoints = append(endpoints, dmarc.RUF...)
		if len(endpoints) > 0 {
			extAuth := checkDMARCExternalAuth(domain, endpoints, d.dnsTransport, d.timeout)
			if len(extAuth) > 0 {
				c.Detail["dmarc_external_auth"] = extAuth
				dmarcExtAuthHeadline = dmarcExternalHeadline(extAuth)
			}
		}
	}

	// Render summary + hint.
	var line2 []string
	if spf != nil {
		line2 = append(line2, "SPF "+spf.All)
	} else {
		line2 = append(line2, "no SPF")
	}
	if dmarc != nil {
		line2 = append(line2, "DMARC p="+dmarc.Policy)
	} else {
		line2 = append(line2, "no DMARC")
	}
	if len(dkim) > 0 {
		var names []string
		for _, s := range dkim {
			names = append(names, s.Name)
		}
		line2 = append(line2, fmt.Sprintf("DKIM (%s)", strings.Join(names, ",")))
	}
	if sts != nil && sts.PolicyPresent {
		line2 = append(line2, "MTA-STS "+sts.Mode)
	}
	if rpt != nil && rpt.Present {
		line2 = append(line2, "TLS-RPT")
	}
	if v := bimiHeadline(bimi); v != "" {
		line2 = append(line2, v)
	}
	if dmarcExtAuthHeadline != "" {
		line2 = append(line2, dmarcExtAuthHeadline)
	}
	if len(mxTLS) > 0 {
		reachable := 0
		for _, m := range mxTLS {
			if m.Reachable {
				reachable++
			}
		}
		if reachable == 0 {
			// Outbound 25 commonly blocked at residential / corporate egress —
			// flag it as "untestable from here" instead of a hard failure.
			line2 = append(line2, fmt.Sprintf("MX STARTTLS untestable (port 25 blocked? %d MX)", len(mxTLS)))
		} else {
			line2 = append(line2, fmt.Sprintf("MX STARTTLS %d/%d", starttlsOK, len(mxTLS)))
		}
	}
	if v := mxDANEHeadline(mxDANE); v != "" {
		line2 = append(line2, v)
	}
	if v := mxIPv6Headline(mxV6); v != "" {
		line2 = append(line2, v)
	}
	if v := dkimKeyHeadline(dkimKeys); v != "" {
		line2 = append(line2, v)
	}
	c.Hint = strings.Join(line2, "  ·  ")

	c.Summary = fmt.Sprintf("%d/100 (%s) — mail-posture audit", score, grade)
	switch {
	case score >= 80:
		c.Status = StatusOK
	case score >= 50:
		c.Status = StatusWarn
	default:
		c.Status = StatusWarn
	}
	return c
}

// isIPLiteral reports whether host looks like an IP literal vs a DNS name.
// IPv6 addresses might be bracketed in URLs but we always strip those.
func isIPLiteral(host string) bool {
	// Naive — IPv4 has dots-only, IPv6 has colons.
	if strings.Count(host, ":") >= 2 {
		return true
	}
	allDigitsDots := true
	for _, c := range host {
		if !(c == '.' || (c >= '0' && c <= '9')) {
			allDigitsDots = false
			break
		}
	}
	return allDigitsDots
}
