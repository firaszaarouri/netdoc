package main

import (
	"strings"
	"testing"
)

// TestDNSBLZoneIntegrity confirms every zone in the curated list carries
// both a tier and a confidence — the metadata the verdict aggregator
// depends on. A missing label would silently fall through the blockerHit
// switch as "other" and downgrade a real production blocker to a
// warn-only finding.
func TestDNSBLZoneIntegrity(t *testing.T) {
	if len(dnsblZones) < 100 {
		t.Errorf("zone list shrunk below 100 entries: got %d", len(dnsblZones))
	}
	for _, z := range dnsblZones {
		if z.Zone == "" {
			t.Errorf("empty Zone in entry: %+v", z)
		}
		if z.Description == "" {
			t.Errorf("empty Description for zone %q", z.Zone)
		}
		if z.Tier == "" {
			t.Errorf("empty Tier for zone %q", z.Zone)
		}
		if z.Confidence == "" {
			t.Errorf("empty Confidence for zone %q", z.Zone)
		}
	}
}

// TestDNSBLZoneUnique catches the dedup regression — the original
// reputation.go shipped truncate.gbudb.net and misc.dnsbl.sorbs.net
// twice each, inflating the zone count for no benefit.
func TestDNSBLZoneUnique(t *testing.T) {
	seen := map[string]int{}
	for _, z := range dnsblZones {
		seen[z.Zone]++
	}
	for zone, n := range seen {
		if n > 1 {
			t.Errorf("zone %q appears %d times", zone, n)
		}
	}
}

// TestBlockerHitClassification confirms the tier+confidence severity
// gate: a hit on a production-grade blocker tier is the only thing
// that triggers StatusFail in checkReputation.
func TestBlockerHitClassification(t *testing.T) {
	cases := []struct {
		name string
		hit  dnsblHit
		want bool
	}{
		{"production composite", dnsblHit{Tier: tierComposite, Confidence: confProduction}, true},
		{"production spam-source", dnsblHit{Tier: tierSpamSrc, Confidence: confProduction}, true},
		{"production exploit", dnsblHit{Tier: tierExploit, Confidence: confProduction}, true},
		{"production botnet", dnsblHit{Tier: tierBotnet, Confidence: confProduction}, true},
		{"operational composite", dnsblHit{Tier: tierComposite, Confidence: confOperational}, true},
		{"heuristic composite", dnsblHit{Tier: tierComposite, Confidence: confHeuristic}, false},
		{"experimental composite", dnsblHit{Tier: tierComposite, Confidence: confExperimental}, false},
		{"production policy", dnsblHit{Tier: tierPolicy, Confidence: confProduction}, false},
		{"production allowlist", dnsblHit{Tier: tierAllowlist, Confidence: confProduction}, false},
		{"production tor", dnsblHit{Tier: tierTor, Confidence: confProduction}, false},
		{"production URI", dnsblHit{Tier: tierURI, Confidence: confProduction}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := blockerHit(c.hit); got != c.want {
				t.Errorf("blockerHit(%+v) = %v, want %v", c.hit, got, c.want)
			}
		})
	}
}

// TestLooksGenericPTR confirms the auto-generated reverse-name detector
// catches the patterns Gmail and Microsoft reject mail on.
func TestLooksGenericPTR(t *testing.T) {
	generic := []string{
		"1-2-3-4.region.isp.com",
		"1.2.3.4.broadband.example.net",
		"ip-1-2-3-4.cust.example.fr",
		"host-1-2-3-4.example.com",
		"pool-1-2-3.cable.example.de",
		"dynamic-203-0-113-45.example.com",
		"dhcp-1-2-3.example.it",
		"dyn-1-2-3.example.es",
		"dialup-1-2-3.example.uk",
		"broadband-1-2-3.example.com",
		"customer-1-2-3.example.com",
		"cust1.example.net",
		"client-1-2.example.com",
	}
	for _, ptr := range generic {
		if !looksGeneric(ptr) {
			t.Errorf("expected generic match for %q", ptr)
		}
	}
	nongeneric := []string{
		"mail.example.com",
		"mx1.gmail.com",
		"smtp.gmail.com",
		"mta.cloudflare.com",
		"ses-smtp.us-west-2.amazonaws.com",
		"outbound.protection.outlook.com",
		"mailhost.example.org",
	}
	for _, ptr := range nongeneric {
		if looksGeneric(ptr) {
			t.Errorf("did not expect generic match for %q", ptr)
		}
	}
}

// TestSentinelFilter confirms the 127.255.255.x sentinel detection
// covers the prefixes operators (Spamhaus, others) return when refusing
// queries from over-quota / public resolvers. Without this filter,
// users running netdoc against 1.1.1.1 would see false-positive
// listings on every IP.
func TestSentinelFilter(t *testing.T) {
	want := []string{"127.255.255."}
	for _, w := range want {
		found := false
		for _, sp := range sentinelPrefixes {
			if sp == w {
				found = true
			}
		}
		if !found {
			t.Errorf("sentinel prefix %q missing from sentinelPrefixes", w)
		}
	}
	// And the prefix actually fires on a real sample.
	answer := "127.255.255.254"
	matched := false
	for _, sp := range sentinelPrefixes {
		if strings.HasPrefix(answer, sp) {
			matched = true
		}
	}
	if !matched {
		t.Errorf("Spamhaus sentinel %s not matched by any prefix", answer)
	}
}

// TestValidAnswer covers the RFC 5782 §2.1 response-space filter that
// guards against zone-hijacking and rate-limit replies. The live smoke
// against github.com surfaced ANT China zones returning 208.98.43.x —
// outside 127.0.0.0/8 — which the old code misread as listings.
func TestValidAnswer(t *testing.T) {
	cases := []struct {
		answer string
		want   bool
	}{
		{"127.0.0.2", true},
		{"127.0.0.5", true},
		{"127.0.0.10", true},
		{"127.0.0.1", true}, // valid by space; refusal check happens in TXT
		{"127.255.255.254", false},
		{"127.255.255.1", false},
		{"208.98.43.16", false}, // ANT China hijacked
		{"10.0.0.1", false},
		{"0.0.0.0", false},
		{"", false},
		{"127.0.0.0", false}, // explicit sentinel for "zero" / null hit
	}
	for _, c := range cases {
		if got := validAnswer(c.answer); got != c.want {
			t.Errorf("validAnswer(%q) = %v, want %v", c.answer, got, c.want)
		}
	}
}

// TestRefusalTXT confirms URIBL / SURBL-style refused-query TXT
// patterns are detected. Without this, a 127.0.0.1 answer plus
// "Query Refused" TXT (URIBL's rate-limit signal) was being counted
// as a real listing.
func TestRefusalTXT(t *testing.T) {
	refused := []string{
		"127.0.0.1 -> Query Refused. See http://uribl.com/refused.shtml",
		"You are over quota for this DNSBL",
		"Rate-limited",
		"rate limited; try a private resolver",
		"Access denied for public resolver",
		"Blocked: public DNS resolver",
		"Excessive queries from your network",
		"Too many queries — see refused page",
	}
	for _, s := range refused {
		if !refusalTXTPatterns.MatchString(s) {
			t.Errorf("expected refusal match for %q", s)
		}
	}
	listings := []string{
		"127.0.0.4: listed in PBL — see https://www.spamhaus.org/lookup/",
		"Spam source observed 2026-04-15 from this IP",
		"Compromised host / exploit signature SPM-123",
		"Open SMTP relay — please secure",
	}
	for _, s := range listings {
		if refusalTXTPatterns.MatchString(s) {
			t.Errorf("did not expect refusal match for %q", s)
		}
	}
}

// TestTierCoverage confirms each major category is represented — guards
// against accidental wipeout (e.g. someone removing all the allowlists).
func TestTierCoverage(t *testing.T) {
	counts := map[zoneTier]int{}
	for _, z := range dnsblZones {
		counts[z.Tier]++
	}
	mustHave := []zoneTier{
		tierComposite, tierSpamSrc, tierExploit, tierPolicy,
		tierProxy, tierMalware, tierBotnet, tierTor,
		tierAllowlist, tierURI, tierRegional, tierBackscat,
	}
	for _, tier := range mustHave {
		if counts[tier] == 0 {
			t.Errorf("tier %q has zero zones", tier)
		}
	}
}

// TestProductionZonesPresent guards against accidental removal of the
// production-grade blockers that drive the StatusFail severity.
func TestProductionZonesPresent(t *testing.T) {
	wantProduction := []string{
		"zen.spamhaus.org",
		"bl.spamcop.net",
		"b.barracudacentral.org",
		"cbl.abuseat.org",
		"bl.mailspike.net",
		"ips.backscatterer.org",
		"ubl.lashback.com",
	}
	have := map[string]bool{}
	for _, z := range dnsblZones {
		if z.Confidence == confProduction {
			have[z.Zone] = true
		}
	}
	for _, w := range wantProduction {
		if !have[w] {
			t.Errorf("expected production-grade zone %q in list", w)
		}
	}
}
