package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// asnInfo holds the IP→ASN mapping returned by Team Cymru's free DNS-based
// IP-to-ASN service. The origin lookup gives ASN + prefix + CC + registry +
// date; an optional second lookup fills the human-readable organization name.
//
// Why Team Cymru DNS: free forever, no API key, no rate limit worth caring
// about, IPv6-native, fits the "single binary, no setup" positioning. See
// https://team-cymru.com/community-services/ip-asn-mapping/
type asnInfo struct {
	ASN      string `json:"asn"`             // "15169"
	Prefix   string `json:"prefix"`          // "8.8.8.0/24"
	Country  string `json:"country"`         // "US"
	Registry string `json:"registry"`        // "arin"
	Date     string `json:"date,omitempty"`  // "1992-12-01"
	Org      string `json:"org,omitempty"`   // "GOOGLE - Google LLC, US"
}

// String renders the ASN as a compact inline label: "AS15169 · GOOGLE · US".
// Cymru's AS<num> records bake the country code into the trailing comma-piece
// of the org name (e.g. "GITHUB - GitHub, Inc., US"); we strip that to avoid
// rendering the CC twice in the same label.
func (a asnInfo) String() string {
	if a.ASN == "" {
		return ""
	}
	parts := []string{"AS" + a.ASN}
	if org := stripCCFromOrg(a.Org, a.Country); org != "" {
		parts = append(parts, truncate(org, 32))
	}
	if a.Country != "" {
		parts = append(parts, a.Country)
	}
	return strings.Join(parts, " · ")
}

// stripCCFromOrg removes a trailing ", XX" country-code suffix from a Cymru
// org string when XX matches the supplied country code. Returns the org
// trimmed of that suffix (and surrounding whitespace).
func stripCCFromOrg(org, cc string) string {
	org = strings.TrimSpace(org)
	if cc == "" || org == "" {
		return org
	}
	suffix := ", " + strings.ToUpper(cc)
	if strings.HasSuffix(strings.ToUpper(org), suffix) {
		return strings.TrimSpace(org[:len(org)-len(suffix)])
	}
	return org
}

// isPrivateIP reports whether an IP is loopback, link-local, RFC1918 or ULA.
// Per-hop ASN lookups skip these because the public Cymru registry has no
// useful info for the user's own LAN segments and the queries just waste time.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// lookupASN performs the two TXT lookups against Team Cymru's zones and
// returns the merged record. The org lookup is best-effort; a failure there
// leaves Org empty but the rest of the info still useful.
func lookupASN(ip net.IP, transport *dnsTransport, timeout time.Duration) (asnInfo, error) {
	qname := cymruQueryName(ip)
	if qname == "" {
		return asnInfo{}, fmt.Errorf("unsupported address family")
	}
	rrs, err := queryDNS(qname, dns.TypeTXT, transport, timeout)
	if err != nil {
		return asnInfo{}, err
	}
	info, ok := parseCymruOriginTXT(rrs)
	if !ok {
		return asnInfo{}, fmt.Errorf("no origin record")
	}
	if info.ASN != "" {
		if rrs2, err := queryDNS("AS"+info.ASN+".asn.cymru.com", dns.TypeTXT, transport, timeout); err == nil {
			if org, ok := parseCymruASTXT(rrs2); ok {
				info.Org = org
			}
		}
	}
	return info, nil
}

// cymruQueryName produces the FQDN under origin.asn.cymru.com (IPv4) or
// origin6.asn.cymru.com (IPv6) for a given IP. Nibbles are reversed the
// same way an in-addr.arpa PTR would be.
func cymruQueryName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}
	if v6 := ip.To16(); v6 != nil {
		nibs := make([]string, 0, 32)
		for i := len(v6) - 1; i >= 0; i-- {
			nibs = append(nibs, fmt.Sprintf("%x", v6[i]&0xf), fmt.Sprintf("%x", v6[i]>>4))
		}
		return strings.Join(nibs, ".") + ".origin6.asn.cymru.com"
	}
	return ""
}

// parseCymruOriginTXT pulls "ASN | prefix | CC | registry | date" out of the
// TXT answer set. Multiple records can come back when the IP sits in nested
// announcements; we return the most-specific (longest-prefix) match.
func parseCymruOriginTXT(rrs []dns.RR) (asnInfo, bool) {
	var best asnInfo
	bestBits := -1
	for _, r := range rrs {
		t, ok := r.(*dns.TXT)
		if !ok {
			continue
		}
		joined := strings.Join(t.Txt, "")
		parts := strings.Split(joined, "|")
		if len(parts) < 4 {
			continue
		}
		info := asnInfo{
			ASN:      strings.TrimSpace(parts[0]),
			Prefix:   strings.TrimSpace(parts[1]),
			Country:  strings.TrimSpace(parts[2]),
			Registry: strings.TrimSpace(parts[3]),
		}
		if len(parts) >= 5 {
			info.Date = strings.TrimSpace(parts[4])
		}
		// Multi-origin records: pick the field listing a single ASN — the
		// "best" most-specific prefix. Cymru's most-specific row usually wins
		// the longest-prefix tiebreaker.
		bits := prefixBitsCIDR(info.Prefix)
		if bits > bestBits {
			bestBits = bits
			best = info
		}
	}
	if best.ASN == "" {
		return asnInfo{}, false
	}
	return best, true
}

// parseCymruASTXT extracts the organization from an AS<num>.asn.cymru.com
// TXT response shaped as "ASN | CC | registry | date | org".
func parseCymruASTXT(rrs []dns.RR) (string, bool) {
	for _, r := range rrs {
		t, ok := r.(*dns.TXT)
		if !ok {
			continue
		}
		joined := strings.Join(t.Txt, "")
		parts := strings.Split(joined, "|")
		if len(parts) >= 5 {
			return strings.TrimSpace(parts[4]), true
		}
	}
	return "", false
}

// prefixBitsCIDR returns the prefix length from a CIDR, or -1 on parse fail.
func prefixBitsCIDR(prefix string) int {
	i := strings.IndexByte(prefix, '/')
	if i < 0 {
		return -1
	}
	var n int
	if _, err := fmt.Sscanf(prefix[i+1:], "%d", &n); err != nil {
		return -1
	}
	return n
}

// lookupASNs runs concurrent Cymru lookups across multiple IPs. Failed
// lookups are silently absent from the map — never fatal to the parent check.
func lookupASNs(ips []net.IP, transport *dnsTransport, timeout time.Duration) map[string]asnInfo {
	out := make(map[string]asnInfo, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			info, err := lookupASN(ip, transport, timeout)
			if err != nil {
				return
			}
			mu.Lock()
			out[ip.String()] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}
