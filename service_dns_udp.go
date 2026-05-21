package main

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS server CHAOS-class fingerprint probe via UDP/53. Used as the
// active service probe when the target IP itself is being scanned at
// port 53 — distinct from dns_chaos.go which queries the *authoritative*
// nameservers for the *target's domain* through the configured resolver.
//
// Three classic CH-class TXT queries (RFC 4892 + BIND legacy):
//
//   version.bind    — software + version (BIND, NSD, Knot, PowerDNS, dnsmasq)
//   hostname.bind   — physical hostname (anycast PoP identification)
//   id.server       — modern RFC 4892 operator-defined identifier
//
// Most hardened modern deployments mask these (REFUSED or a generic
// string); the absence of a response is itself a posture signal.

func probeDNSUDP(addr, host string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "DNS"}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}

	client := &dns.Client{Net: "udp", Timeout: timeout}

	ver := chaosTXTAt(client, addr, "version.bind.")
	hostname := chaosTXTAt(client, addr, "hostname.bind.")
	id := chaosTXTAt(client, addr, "id.server.")

	if ver == "" && hostname == "" && id == "" {
		// Either the port is silent or refuses CHAOS. The classifier in
		// ports_udp_linux.go will distinguish closed vs filtered; we just
		// can't extract a banner.
		info.Product = ""
		return info
	}

	info.Extra = map[string]string{}
	if ver != "" {
		info.Extra["version_bind"] = ver
		info.Version = parseVersionString(ver)
		info.Banner = ver
		// Detect well-known DNS server families from version strings.
		switch {
		case containsCaseInsensitive(ver, "bind"):
			info.Product = "BIND"
		case containsCaseInsensitive(ver, "unbound"):
			info.Product = "Unbound"
		case containsCaseInsensitive(ver, "knot"):
			info.Product = "Knot"
		case containsCaseInsensitive(ver, "powerdns"), containsCaseInsensitive(ver, "PowerDNS"):
			info.Product = "PowerDNS"
		case containsCaseInsensitive(ver, "nsd"):
			info.Product = "NSD"
		case containsCaseInsensitive(ver, "dnsmasq"):
			info.Product = "dnsmasq"
		case containsCaseInsensitive(ver, "coredns"):
			info.Product = "CoreDNS"
		default:
			info.Product = "DNS"
		}
	}
	if hostname != "" {
		info.Extra["hostname_bind"] = hostname
	}
	if id != "" {
		info.Extra["id_server"] = id
	}

	_ = host
	return info
}

// chaosTXTAt queries the given DNS server address (host:port) for a
// CH-class TXT record, returning the joined string or empty on any error.
func chaosTXTAt(client *dns.Client, addr, qname string) string {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	m.RecursionDesired = false
	resp, _, err := client.Exchange(m, addr)
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return ""
	}
	var parts []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			parts = append(parts, t.Txt...)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// parseVersionString attempts to extract a "N.N(.N)?(...)?" version
// number from a CHAOS version.bind response. Returns empty on no match.
func parseVersionString(s string) string {
	var v strings.Builder
	started := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v.WriteRune(c)
			started = true
		} else if started && (c == '.' || c == '-' || c == '_' || c == 'p') {
			v.WriteRune(c)
		} else if started {
			break
		}
	}
	out := strings.TrimRight(v.String(), ".-_p")
	if !strings.ContainsRune(out, '.') {
		return ""
	}
	return out
}

// containsCaseInsensitive is a lowercase substring match.
func containsCaseInsensitive(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

