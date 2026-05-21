package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// IP-reputation check via DNSBL (DNS-based blackhole lists) + FCrDNS
// (Forward-Confirmed reverse DNS) per RFC 8499 §3. The DNSBL probe
// matrix runs every resolved IPv4 against every zone in parallel; FCrDNS
// runs per IP and classifies the reverse-DNS posture used by every
// major mail receiver (Gmail, Microsoft, Apple, AWS SES) to gate inbound.
//
// Each zone carries a tier and confidence label so the verdict can
// distinguish a production-grade composite blocker (Spamhaus ZEN) from
// a regional list with sketchy listing criteria.

// zoneTier categorises what kind of badness the zone tracks.
type zoneTier string

const (
	tierComposite  zoneTier = "composite"   // multi-source composite blocker
	tierSpamSrc    zoneTier = "spam"        // confirmed spam-source
	tierExploit    zoneTier = "exploit"     // exploited / compromised hosts
	tierPolicy     zoneTier = "policy"      // preventive / policy lists
	tierProxy      zoneTier = "proxy"       // open relay / SOCKS / HTTP proxy
	tierMalware    zoneTier = "malware"     // malware / phishing
	tierBotnet     zoneTier = "botnet"      // botnet C2 / drone
	tierTor        zoneTier = "tor"         // Tor exit node
	tierDynamic    zoneTier = "dynamic"     // dynamic IP allocation
	tierURI        zoneTier = "uri"         // URI / domain reputation
	tierAllowlist  zoneTier = "allowlist"   // positive reputation
	tierRegional   zoneTier = "regional"    // regional / country-specific
	tierBackscat   zoneTier = "backscatter" // backscatter / bounce-source
)

// confLevel grades how seriously a hit on this zone should be taken.
//
//	production   — used by major MTAs (Gmail, Microsoft, Apple, AWS SES)
//	operational  — reputable, real-world signal, occasional false positives
//	heuristic    — informational, false-positive prone
//	experimental — research / regional / low corpus
type confLevel string

const (
	confProduction   confLevel = "production"
	confOperational  confLevel = "operational"
	confHeuristic    confLevel = "heuristic"
	confExperimental confLevel = "experimental"
)

// dnsblZone is one configured blacklist (or allowlist) zone.
type dnsblZone struct {
	Zone        string
	Description string
	Tier        zoneTier
	Confidence  confLevel
}

// dnsblZones is the curated set of zones netdoc probes. Curation focuses
// on currently-operational lists with documented criteria; defunct zones
// (SpamCannibal 2018, Five-Ten-SG, SORBS dial-up since the 2024
// retirement) are excluded.
var dnsblZones = []dnsblZone{
	// === Production-grade composite blockers — used by Gmail / Microsoft / Apple / AWS SES.
	{"zen.spamhaus.org", "Spamhaus ZEN (composite)", tierComposite, confProduction},
	{"bl.spamhaus.org", "Spamhaus combined", tierComposite, confProduction},
	{"sbl.spamhaus.org", "Spamhaus SBL", tierComposite, confProduction},
	{"xbl.spamhaus.org", "Spamhaus XBL (exploits)", tierExploit, confProduction},
	{"pbl.spamhaus.org", "Spamhaus PBL (policy)", tierPolicy, confProduction},
	{"dbl.spamhaus.org", "Spamhaus DBL (domains)", tierURI, confProduction},
	{"zrd.spamhaus.org", "Spamhaus ZRD (zero-rep domains)", tierURI, confProduction},
	{"b.barracudacentral.org", "Barracuda Reputation", tierComposite, confProduction},
	{"bl.spamcop.net", "SpamCop", tierSpamSrc, confProduction},
	{"cbl.abuseat.org", "CBL (Composite Blocking)", tierExploit, confProduction},
	{"psbl.surriel.com", "PSBL", tierSpamSrc, confProduction},
	{"bl.mailspike.net", "Mailspike BL", tierSpamSrc, confProduction},
	{"z.mailspike.net", "Mailspike Z-list", tierSpamSrc, confProduction},
	{"rep.mailspike.net", "Mailspike rep", tierComposite, confProduction},
	{"truncate.gbudb.net", "GBUdb truncate", tierSpamSrc, confProduction},
	{"ix.dnsbl.manitu.net", "NiX Spam (Heise)", tierSpamSrc, confProduction},

	// === Production allowlists — positive reputation signal, hit = good.
	{"swl.spamhaus.org", "Spamhaus SWL (whitelist)", tierAllowlist, confProduction},
	{"list.dnswl.org", "DNSWL allowlist", tierAllowlist, confProduction},
	{"wl.score.mailspike.net", "Mailspike whitelist", tierAllowlist, confProduction},
	{"nobl.junkemailfilter.com", "JunkEmail NoBL", tierAllowlist, confProduction},
	{"iadb.isipp.com", "ISIPP IADB allowlist", tierAllowlist, confProduction},
	{"iadb2.isipp.com", "ISIPP IADB-2 allowlist", tierAllowlist, confOperational},

	// === Backscatter (production).
	{"ips.backscatterer.org", "Backscatterer.org", tierBackscat, confProduction},
	{"backscatter.uceprotect.net", "UCEPROTECT backscatter", tierBackscat, confOperational},
	{"backscatter.spameatingmonkey.net", "SpamEatingMonkey backscatter", tierBackscat, confOperational},

	// === Lashback — production.
	{"ubl.lashback.com", "Lashback UBL", tierSpamSrc, confProduction},
	{"ubl.unsubscore.com", "Lashback Unsubscore", tierSpamSrc, confProduction},

	// === UCEPROTECT tiers.
	{"dnsbl-1.uceprotect.net", "UCEPROTECT L1 (specific)", tierPolicy, confOperational},
	{"dnsbl-2.uceprotect.net", "UCEPROTECT L2 (allocation)", tierPolicy, confHeuristic},
	{"dnsbl-3.uceprotect.net", "UCEPROTECT L3 (ASN)", tierPolicy, confHeuristic},

	// === SORBS family — operational, some sub-tiers more aggressive.
	{"dnsbl.sorbs.net", "SORBS aggregate", tierComposite, confOperational},
	{"spam.dnsbl.sorbs.net", "SORBS spam", tierSpamSrc, confOperational},
	{"new.spam.dnsbl.sorbs.net", "SORBS new spam", tierSpamSrc, confOperational},
	{"recent.dnsbl.sorbs.net", "SORBS recent", tierSpamSrc, confOperational},
	{"old.dnsbl.sorbs.net", "SORBS old", tierSpamSrc, confHeuristic},
	{"escalations.dnsbl.sorbs.net", "SORBS escalations", tierSpamSrc, confOperational},
	{"socks.dnsbl.sorbs.net", "SORBS SOCKS", tierProxy, confOperational},
	{"misc.dnsbl.sorbs.net", "SORBS misc proxies", tierProxy, confOperational},
	{"smtp.dnsbl.sorbs.net", "SORBS open relays", tierProxy, confOperational},
	{"http.dnsbl.sorbs.net", "SORBS HTTP", tierProxy, confOperational},
	{"web.dnsbl.sorbs.net", "SORBS web", tierProxy, confHeuristic},
	{"zombie.dnsbl.sorbs.net", "SORBS zombie", tierBotnet, confOperational},
	{"block.dnsbl.sorbs.net", "SORBS block", tierPolicy, confOperational},
	{"virus.dnsbl.sorbs.net", "SORBS virus", tierMalware, confOperational},
	{"safe.dnsbl.sorbs.net", "SORBS safe", tierAllowlist, confHeuristic},
	{"problems.dnsbl.sorbs.net", "SORBS problems", tierSpamSrc, confHeuristic},
	{"proxies.dnsbl.sorbs.net", "SORBS proxies", tierProxy, confOperational},
	{"relays.dnsbl.sorbs.net", "SORBS relays", tierProxy, confOperational},
	{"spews.dnsbl.sorbs.net", "SORBS SPEWS", tierSpamSrc, confHeuristic},
	{"l1.bbfh.ext.sorbs.net", "SORBS BBFH L1", tierBotnet, confHeuristic},
	{"l3.bbfh.ext.sorbs.net", "SORBS BBFH L3", tierBotnet, confExperimental},

	// === MSRBL family — operational.
	{"phishing.rbl.msrbl.net", "MSRBL phishing", tierMalware, confOperational},
	{"virus.rbl.msrbl.net", "MSRBL virus", tierMalware, confOperational},
	{"combined.rbl.msrbl.net", "MSRBL combined", tierComposite, confOperational},
	{"images.rbl.msrbl.net", "MSRBL images", tierSpamSrc, confHeuristic},
	{"web.rbl.msrbl.net", "MSRBL web", tierSpamSrc, confHeuristic},
	{"spam.rbl.msrbl.net", "MSRBL spam", tierSpamSrc, confOperational},

	// === SpamRats family — operational.
	{"dyna.spamrats.com", "SpamRats dynamic", tierDynamic, confOperational},
	{"noptr.spamrats.com", "SpamRats NoPTR", tierPolicy, confOperational},
	{"spam.spamrats.com", "SpamRats spam", tierSpamSrc, confOperational},
	{"all.spamrats.com", "SpamRats aggregate", tierComposite, confOperational},

	// === SpamEatingMonkey — operational.
	{"bl.spameatingmonkey.net", "SpamEatingMonkey BL", tierSpamSrc, confOperational},
	{"badnets.spameatingmonkey.net", "SpamEatingMonkey BadNets", tierPolicy, confOperational},
	{"netbl.spameatingmonkey.net", "SpamEatingMonkey NetBL", tierSpamSrc, confHeuristic},
	{"urired.spameatingmonkey.net", "SpamEatingMonkey URI red", tierURI, confOperational},
	{"uribl.spameatingmonkey.net", "SpamEatingMonkey URIBL", tierURI, confOperational},

	// === URIBL family.
	{"multi.uribl.com", "URIBL multi", tierURI, confProduction},
	{"black.uribl.com", "URIBL black", tierURI, confProduction},
	{"grey.uribl.com", "URIBL grey", tierURI, confOperational},
	{"red.uribl.com", "URIBL red", tierURI, confHeuristic},

	// === SURBL family.
	{"multi.surbl.org", "SURBL multi", tierURI, confProduction},
	{"ph.surbl.org", "SURBL phishing", tierMalware, confOperational},
	{"mw.surbl.org", "SURBL malware", tierMalware, confOperational},

	// === DroneBL / botnet.
	{"dnsbl.dronebl.org", "DroneBL", tierBotnet, confOperational},
	{"rbl.efnetrbl.org", "EFnet RBL", tierBotnet, confOperational},

	// === Composite / catch-all.
	{"all.s5h.net", "s5h.net all", tierComposite, confOperational},
	{"db.wpbl.info", "WPBL", tierSpamSrc, confOperational},
	{"bl.score.senderscore.com", "SenderScore", tierComposite, confProduction},
	{"bl.blocklist.de", "blocklist.de", tierSpamSrc, confOperational},
	{"bl.0spam.org", "0spam", tierSpamSrc, confOperational},
	{"rbl.interserver.net", "InterServer RBL", tierComposite, confOperational},
	{"hostkarma.junkemailfilter.com", "JunkEmail HostKarma", tierComposite, confOperational},
	{"orvedb.aupads.org", "ORVEDB AUPADS", tierSpamSrc, confHeuristic},
	{"rsbl.aupads.org", "RSBL AUPADS", tierSpamSrc, confHeuristic},
	{"all.bl.octopull.co.uk", "Octopull all", tierSpamSrc, confExperimental},
	{"opm.tornevall.org", "Tornevall OPM", tierProxy, confOperational},
	{"bl.deadbeef.com", "deadbeef BL", tierSpamSrc, confExperimental},
	{"feb.spamlab.com", "SpamLab feb", tierSpamSrc, confHeuristic},
	{"rbl.spamlab.com", "SpamLab RBL", tierSpamSrc, confHeuristic},
	{"dnsbl.justspam.org", "JustSpam", tierSpamSrc, confOperational},
	{"dnsbl.kempt.net", "kempt.net BL", tierSpamSrc, confExperimental},

	// === Tor exit nodes — informational, not actionable for mail.
	{"tor.dan.me.uk", "Tor exit (dan.me.uk)", tierTor, confOperational},
	{"tor.dnsbl.sectoor.de", "Sectoor Tor", tierTor, confOperational},
	{"exitnodes.tor.dnsbl.sectoor.de", "Sectoor Tor exit", tierTor, confOperational},

	// === ANT (China) — operational on Asia-Pacific corpus.
	{"cbl.anti-spam.org.cn", "ANT China CBL", tierSpamSrc, confOperational},
	{"cdl.anti-spam.org.cn", "ANT China CDL", tierComposite, confOperational},
	{"cblplus.anti-spam.org.cn", "ANT China CBL+", tierSpamSrc, confOperational},
	{"cblless.anti-spam.org.cn", "ANT China CBL-", tierSpamSrc, confHeuristic},

	// === RBL.JP (Japan) — operational on Asia-Pacific corpus.
	{"all.rbl.jp", "RBL.JP all", tierComposite, confOperational},
	{"dyndns.rbl.jp", "RBL.JP dyndns", tierDynamic, confOperational},
	{"short.rbl.jp", "RBL.JP short", tierSpamSrc, confOperational},
	{"url.rbl.jp", "RBL.JP url", tierURI, confOperational},

	// === European regional.
	{"dnsrbl.swinog.ch", "Swinog Swiss BL", tierRegional, confOperational},
	{"uribl.swinog.ch", "Swinog URIBL", tierURI, confOperational},
	{"black.dnsbl.brukalai.lt", "Brukalai Lithuania BL", tierRegional, confExperimental},
	{"light.dnsbl.brukalai.lt", "Brukalai Lithuania light", tierRegional, confExperimental},
	{"forbidden.icm.edu.pl", "ICM Poland forbidden", tierRegional, confExperimental},
	{"singular.ttk.pte.hu", "TTK Hungary URI", tierURI, confExperimental},
	{"dnsbl.spam-rbl.fr", "Spam-RBL France", tierRegional, confExperimental},
	{"bl.suomispam.net", "Suomispam Finland", tierRegional, confExperimental},

	// === Other regional / specialty.
	{"dnsbl.dnsbl.com.ar", "DNSBL Argentina", tierRegional, confExperimental},
	{"dnsbl.calivent.com.pe", "Calivent Peru", tierRegional, confExperimental},
	{"bl.scientificspam.net", "Scientific Spam", tierSpamSrc, confExperimental},
	{"dnsbl.zapbl.net", "ZapBL", tierSpamSrc, confExperimental},
	{"relays.nether.net", "Nether relays", tierProxy, confExperimental},
	{"unsure.nether.net", "Nether unsure", tierSpamSrc, confExperimental},
}

// sentinelPrefixes — DNSBL operators return responses in 127.255.255.0/24
// when the querying resolver is rate-limited or blocked (Spamhaus rejects
// queries from public resolvers like 1.1.1.1). These look like listings
// but are actually error sentinels. Filter them out.
var sentinelPrefixes = []string{"127.255.255.", "127.0.0.0"}

// refusalTXTPatterns matches TXT-record content that DNSBL operators
// return alongside 127.0.0.1 answers to signal a refused / rate-limited
// query (URIBL, SURBL, and others use this convention). Without this
// check, a refused URIBL query is misread as a real listing because
// 127.0.0.1 is a perfectly valid DNSBL listing answer on most zones.
var refusalTXTPatterns = regexp.MustCompile(
	`(?i)(query refused|rate[ -]?limit|over[ -]?quota|blocked.*(resolver|dns)|public.*resolver|access.*denied|excessive.*queries|too.*many.*queries|see.*refused)`,
)

// validAnswer returns true when the DNSBL response is a plausible
// listing — answers in 127.0.0.0/8 (the DNSBL response space per
// RFC 5782 §2.1) excluding the 127.255.255.0/24 sentinel range.
// Anything outside 127.0.0.0/8 indicates the zone has been hijacked,
// retired with a wildcard parking entity, or intercepted by an
// upstream resolver — some now-defunct zones still resolve to non-127
// junk for any query.
func validAnswer(s string) bool {
	if !strings.HasPrefix(s, "127.") {
		return false
	}
	for _, sp := range sentinelPrefixes {
		if strings.HasPrefix(s, sp) {
			return false
		}
	}
	return true
}

// dnsblHit records a single blacklist match.
type dnsblHit struct {
	IP          string    `json:"ip"`
	Zone        string    `json:"zone"`
	Description string    `json:"description"`
	Tier        zoneTier  `json:"tier"`
	Confidence  confLevel `json:"confidence"`
	Answer      string    `json:"answer,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// fcrdnsResult is the Forward-Confirmed reverse DNS verdict per IP.
//
//	pass         — PTR → forward → original IP round-trip succeeded
//	no_ptr       — no PTR record for the IP
//	no_forward   — PTR points to a hostname with no A/AAAA
//	mismatch     — PTR's forward A/AAAA doesn't include the original IP
//	generic_ptr  — PTR is present but matches a generic ISP/dynamic pattern
//
// Major mail receivers reject mail from IPs that fail FCrDNS regardless of
// SPF/DMARC — surfacing this gap is high signal for mail-posture work.
type fcrdnsResult struct {
	IP         string   `json:"ip"`
	PTRs       []string `json:"ptrs,omitempty"`
	ForwardIPs []string `json:"forward_ips,omitempty"`
	Verdict    string   `json:"verdict"`
	GenericPTR bool     `json:"generic_ptr,omitempty"`
}

// genericPTRPatterns matches PTRs that encode the IP — these typically
// indicate consumer/dynamic allocations and most mail receivers reject
// them. RFC 8499 §3 calls these "auto-generated reverse names".
var genericPTRPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\d+[-.]\d+[-.]\d+[-.]\d+\.`), // 1.2.3.4.isp / 1-2-3-4.isp
	regexp.MustCompile(`(^|\.)ip[-_]?\d+[-.]?\d+`),     // ip-1-2-3-4.isp
	regexp.MustCompile(`(^|\.)host[-_]?\d+`),           // host-1-2-3-4.isp
	regexp.MustCompile(`(^|\.)pool[-_]?\d+`),           // pool-1-2-3.isp
	regexp.MustCompile(`(^|\.)dynamic[-_]?\d+`),        // dynamic-1-2-3.isp
	regexp.MustCompile(`(^|\.)dhcp[-_]?\d+`),           // dhcp-1-2-3.isp
	regexp.MustCompile(`(^|\.)dyn[-_]?\d+[-.]`),        // dyn-1-2-3.isp
	regexp.MustCompile(`(^|\.)dial(up)?[-_]?\d+`),      // dialup-1-2-3.isp
	regexp.MustCompile(`(^|\.)broadband[-_]?\d+`),      // broadband-1-2-3.isp
	regexp.MustCompile(`(^|\.)cust(omer)?[-_]?\d+`),    // customer-1-2-3.isp
	regexp.MustCompile(`(^|\.)client[-_]?\d+[-.]`),     // client-1-2.isp
}

// looksGeneric returns true when the PTR name encodes the IP in a way
// that matches the auto-generated patterns major mail receivers reject.
func looksGeneric(ptr string) bool {
	p := strings.ToLower(strings.TrimSuffix(ptr, "."))
	for _, re := range genericPTRPatterns {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// probeFCrDNS runs Forward-Confirmed reverse DNS for a single IP.
func probeFCrDNS(ip net.IP, transport *dnsTransport, timeout time.Duration) fcrdnsResult {
	res := fcrdnsResult{IP: ip.String(), Verdict: "no_ptr"}
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		res.Verdict = "no_ptr"
		return res
	}
	rrs, err := queryDNS(arpa, dns.TypePTR, transport, perProbe)
	if err != nil || len(rrs) == 0 {
		return res
	}
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok {
			name := strings.TrimSuffix(ptr.Ptr, ".")
			if name == "" {
				continue
			}
			res.PTRs = append(res.PTRs, name)
		}
	}
	if len(res.PTRs) == 0 {
		return res
	}
	// Forward-lookup the first PTR. Walk all PTRs only if the first fails;
	// real-world IPs almost always have one canonical reverse name.
	for _, ptr := range res.PTRs {
		qtype := uint16(dns.TypeA)
		if ip.To4() == nil {
			qtype = dns.TypeAAAA
		}
		fwd, err := queryDNS(ptr, qtype, transport, perProbe)
		if err != nil || len(fwd) == 0 {
			continue
		}
		var fwdIPs []net.IP
		for _, rr := range fwd {
			switch v := rr.(type) {
			case *dns.A:
				if v.A != nil {
					fwdIPs = append(fwdIPs, v.A)
					res.ForwardIPs = append(res.ForwardIPs, v.A.String())
				}
			case *dns.AAAA:
				if v.AAAA != nil {
					fwdIPs = append(fwdIPs, v.AAAA)
					res.ForwardIPs = append(res.ForwardIPs, v.AAAA.String())
				}
			}
		}
		if len(fwdIPs) == 0 {
			res.Verdict = "no_forward"
			continue
		}
		for _, f := range fwdIPs {
			if f.Equal(ip) {
				res.Verdict = "pass"
				if looksGeneric(ptr) {
					res.GenericPTR = true
					res.Verdict = "generic_ptr"
				}
				return res
			}
		}
		res.Verdict = "mismatch"
	}
	return res
}

// reputationResult collects DNSBL + FCrDNS findings for all resolved IPs.
type reputationResult struct {
	IPsChecked     int            `json:"ips_checked"`
	ZonesChecked   int            `json:"zones_checked"`
	Hits           []dnsblHit     `json:"hits,omitempty"`
	FCrDNS         []fcrdnsResult `json:"fcrdns,omitempty"`
	ErrorsObserved bool           `json:"errors_observed,omitempty"`
}

// probeReputation runs the full IPs × zones DNSBL matrix in parallel
// plus the per-IP FCrDNS probe. Errors-observed=true when one or more
// zones returned a sentinel 127.255.255.x answer (rate-limited resolver).
func probeReputation(ips []net.IP, transport *dnsTransport, timeout time.Duration) *reputationResult {
	res := &reputationResult{
		IPsChecked:   len(ips),
		ZonesChecked: len(dnsblZones),
	}
	if len(ips) == 0 {
		return res
	}
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Per-IP FCrDNS.
	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			r := probeFCrDNS(ip, transport, perProbe)
			mu.Lock()
			res.FCrDNS = append(res.FCrDNS, r)
			mu.Unlock()
		}(ip)
	}

	// DNSBL matrix — IPv4 only (DNSBL family doesn't widely support v6).
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		ipStr := ip.String()
		reversed := fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
		for _, z := range dnsblZones {
			wg.Add(1)
			go func(ipStr, rev string, z dnsblZone) {
				defer wg.Done()
				qname := rev + "." + z.Zone
				rrs, err := queryDNS(qname, dns.TypeA, transport, perProbe)
				if err != nil || len(rrs) == 0 {
					return
				}
				hit := dnsblHit{
					IP:          ipStr,
					Zone:        z.Zone,
					Description: z.Description,
					Tier:        z.Tier,
					Confidence:  z.Confidence,
				}
				for _, rr := range rrs {
					if a, ok := rr.(*dns.A); ok && a.A != nil {
						hit.Answer = a.A.String()
						break
					}
				}
				if hit.Answer == "" {
					return
				}
				// Filter: response must be inside the RFC 5782 §2.1
				// DNSBL response space (127.0.0.0/8) and outside the
				// 127.255.255.0/24 sentinel range. Anything else is a
				// hijacked zone, wildcard parking, or rate-limit reply.
				if !validAnswer(hit.Answer) {
					mu.Lock()
					res.ErrorsObserved = true
					mu.Unlock()
					return
				}
				// Optional TXT for the human-readable reason. Best-effort.
				if txtRRs, err := queryDNS(qname, dns.TypeTXT, transport, perProbe); err == nil {
					for _, rr := range txtRRs {
						if t, ok := rr.(*dns.TXT); ok {
							hit.Reason = strings.Join(t.Txt, " ")
							break
						}
					}
				}
				// Even with a 127.0.0.x answer, an explicit refusal in
				// the TXT (URIBL "Query Refused" pattern at 127.0.0.1)
				// is a rate-limit, not a listing.
				if hit.Reason != "" && refusalTXTPatterns.MatchString(hit.Reason) {
					mu.Lock()
					res.ErrorsObserved = true
					mu.Unlock()
					return
				}
				mu.Lock()
				res.Hits = append(res.Hits, hit)
				mu.Unlock()
			}(ipStr, reversed, z)
		}
	}
	wg.Wait()
	return res
}

// blockerHit returns true when the hit is on a production-grade
// composite blocker, spam-source, exploit, or botnet zone — the kind
// that will get mail rejected by Gmail / Microsoft / AWS SES.
func blockerHit(h dnsblHit) bool {
	if h.Confidence != confProduction && h.Confidence != confOperational {
		return false
	}
	switch h.Tier {
	case tierComposite, tierSpamSrc, tierExploit, tierBotnet:
		return true
	}
	return false
}

// checkReputation runs DNSBL listing probes + FCrDNS on every resolved
// IPv4 address. Hits get severity by tier+confidence:
//
//	production-blocker hit → StatusFail (mail will be rejected)
//	other operational hit  → StatusWarn (deliverability degraded)
//	heuristic/experimental → informational note only
//	FCrDNS fail/generic    → contributes to severity per major-MTA policy
func (d *diagnosis) checkReputation() Check {
	c := Check{Name: "Reputation"}
	if !d.resolved || len(d.ipv4) == 0 {
		c.Status = StatusSkip
		c.Summary = "skipped — no IPv4 addresses"
		return c
	}
	res := probeReputation(d.ipv4, d.dnsTransport, d.timeout)
	c.Detail = map[string]any{
		"ips_checked":   res.IPsChecked,
		"zones_checked": res.ZonesChecked,
		"hits":          res.Hits,
		"fcrdns":        res.FCrDNS,
	}

	// Aggregate by IP and severity.
	type ipFindings struct {
		ip           string
		blockers     []dnsblHit
		other        []dnsblHit
		allowlisted  []dnsblHit
		fcrdnsResult fcrdnsResult
		hasFCrDNS    bool
	}
	byIP := map[string]*ipFindings{}
	for _, h := range res.Hits {
		f, ok := byIP[h.IP]
		if !ok {
			f = &ipFindings{ip: h.IP}
			byIP[h.IP] = f
		}
		switch {
		case h.Tier == tierAllowlist:
			f.allowlisted = append(f.allowlisted, h)
		case blockerHit(h):
			f.blockers = append(f.blockers, h)
		default:
			f.other = append(f.other, h)
		}
	}
	for _, r := range res.FCrDNS {
		f, ok := byIP[r.IP]
		if !ok {
			f = &ipFindings{ip: r.IP}
			byIP[r.IP] = f
		}
		f.fcrdnsResult = r
		f.hasFCrDNS = true
	}

	// Determine overall severity.
	worst := StatusOK
	totalBlockers := 0
	totalOther := 0
	totalAllow := 0
	fcrdnsBad := 0
	for _, f := range byIP {
		totalBlockers += len(f.blockers)
		totalOther += len(f.other)
		totalAllow += len(f.allowlisted)
		if f.hasFCrDNS {
			switch f.fcrdnsResult.Verdict {
			case "no_ptr", "no_forward", "mismatch", "generic_ptr":
				fcrdnsBad++
			}
		}
	}
	switch {
	case totalBlockers > 0:
		worst = StatusFail
	case totalOther > 0 || fcrdnsBad > 0:
		worst = StatusWarn
	}

	// Build the hint as a sorted, per-IP report.
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var hintLines []string
	for _, ip := range ips {
		f := byIP[ip]
		if len(f.blockers) > 0 {
			zones := zoneDescs(f.blockers)
			hintLines = append(hintLines, fmt.Sprintf("%s production blocklist: %s", ip, strings.Join(zones, ", ")))
		}
		if len(f.other) > 0 {
			zones := zoneDescs(f.other)
			hintLines = append(hintLines, fmt.Sprintf("%s also on: %s", ip, strings.Join(zones, ", ")))
		}
		if len(f.allowlisted) > 0 {
			zones := zoneDescs(f.allowlisted)
			hintLines = append(hintLines, fmt.Sprintf("%s allowlisted on: %s", ip, strings.Join(zones, ", ")))
		}
		if f.hasFCrDNS {
			switch f.fcrdnsResult.Verdict {
			case "no_ptr":
				hintLines = append(hintLines, fmt.Sprintf("%s FCrDNS: no PTR record (Gmail/Microsoft reject)", ip))
			case "no_forward":
				hintLines = append(hintLines, fmt.Sprintf("%s FCrDNS: PTR has no forward A/AAAA (%s)", ip, strings.Join(f.fcrdnsResult.PTRs, ", ")))
			case "mismatch":
				hintLines = append(hintLines, fmt.Sprintf("%s FCrDNS: forward IPs %s don't match", ip, strings.Join(f.fcrdnsResult.ForwardIPs, ", ")))
			case "generic_ptr":
				hintLines = append(hintLines, fmt.Sprintf("%s FCrDNS: generic PTR %s (consumer-IP pattern; Gmail rejects)", ip, strings.Join(f.fcrdnsResult.PTRs, ", ")))
			}
		}
	}

	if worst == StatusOK {
		c.Status = StatusOK
		c.Summary = fmt.Sprintf("clean across %d blacklist%s + FCrDNS (%d IP%s)",
			res.ZonesChecked, plural(res.ZonesChecked),
			res.IPsChecked, plural(res.IPsChecked))
		if totalAllow > 0 {
			c.Summary += fmt.Sprintf(" — %d allowlist hit%s", totalAllow, plural(totalAllow))
			c.Hint = strings.Join(hintLines, "\n")
		}
		if res.ErrorsObserved {
			if c.Hint != "" {
				c.Hint += "\n"
			}
			c.Hint += "some DNSBLs declined to answer (Spamhaus blocks public-resolver queries — try --dns udp:<your-resolver>)"
		}
		return c
	}

	c.Status = worst
	parts := []string{}
	if totalBlockers > 0 {
		parts = append(parts, fmt.Sprintf("%d production-blocker hit%s", totalBlockers, plural(totalBlockers)))
	}
	if totalOther > 0 {
		parts = append(parts, fmt.Sprintf("%d secondary hit%s", totalOther, plural(totalOther)))
	}
	if fcrdnsBad > 0 {
		parts = append(parts, fmt.Sprintf("%d FCrDNS issue%s", fcrdnsBad, plural(fcrdnsBad)))
	}
	c.Summary = strings.Join(parts, ", ") + fmt.Sprintf(" across %d zones (%d IP%s)",
		res.ZonesChecked, res.IPsChecked, plural(res.IPsChecked))
	c.Hint = strings.Join(hintLines, "\n")
	return c
}

// zoneDescs returns the human descriptions for a slice of hits.
func zoneDescs(hits []dnsblHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Description)
	}
	return out
}
