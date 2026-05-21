package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Root server we start the iterative trace from. a.root-servers.net is the
// historical "first" root and is anycast world-wide. If networks block direct
// DNS to it they generally block direct DNS to all roots, so trying just one
// is fine — we fail fast rather than fan out across 13 servers.
const (
	rootServerAddr = "198.41.0.4:53"
	rootServerName = "a.root-servers.net"
)

// delegationStep records what one level of the iterative walk learned.
type delegationStep struct {
	Level         int      `json:"level"`
	Zone          string   `json:"zone"`
	Server        string   `json:"server"`
	ServerName    string   `json:"server_name,omitempty"`
	NSRecords     []string `json:"ns,omitempty"`
	Authoritative bool     `json:"authoritative,omitempty"`
	RTTms         float64  `json:"rtt_ms"`
}

// traceDelegation walks the DNS delegation from a root server down to the
// authoritative servers for host — the way `dig +trace` does. At each
// referral it picks the first NS, resolves it (via glue from the Additional
// section, or falls back to the system resolver), and queries that server
// next with RD=false so we get referrals back, not recursive answers.
func traceDelegation(host string, timeout time.Duration) ([]delegationStep, error) {
	var steps []delegationStep

	server := rootServerAddr
	serverName := rootServerName
	fqdn := dns.Fqdn(host)

	for level := 0; level < 12; level++ {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeA)
		m.RecursionDesired = false

		c := &dns.Client{Net: "udp", Timeout: timeout}
		start := time.Now()
		r, _, err := c.Exchange(m, server)
		rtt := time.Since(start)
		if err != nil || r == nil {
			return steps, err
		}

		var nsNames []string
		zone := "."
		for _, rr := range r.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, strings.TrimSuffix(ns.Ns, "."))
				if zone == "." {
					z := strings.TrimSuffix(ns.Header().Name, ".")
					if z != "" {
						zone = z
					}
				}
			}
		}
		// Some authoritative servers omit NS records from the Authority
		// section in their replies — in that case fall back to the question
		// name rather than rendering "." as the zone.
		if r.Authoritative && zone == "." {
			zone = strings.TrimSuffix(fqdn, ".")
		}

		steps = append(steps, delegationStep{
			Level:         level,
			Zone:          zone,
			Server:        server,
			ServerName:    serverName,
			NSRecords:     nsNames,
			Authoritative: r.Authoritative,
			RTTms:         ms(rtt),
		})

		if r.Authoritative || len(r.Answer) > 0 {
			break
		}
		if len(nsNames) == 0 {
			break
		}

		// Pick the next NS — prefer one whose glue we have in Additional.
		var nextIP, nextName string
		for _, rr := range r.Extra {
			a, ok := rr.(*dns.A)
			if !ok {
				continue
			}
			ah := strings.TrimSuffix(a.Header().Name, ".")
			for _, n := range nsNames {
				if n == ah {
					nextIP, nextName = a.A.String(), n
					break
				}
			}
			if nextIP != "" {
				break
			}
		}
		if nextIP == "" {
			// No glue — resolve the first NS via the system resolver.
			ips, err := net.DefaultResolver.LookupHost(context.Background(), nsNames[0])
			if err != nil || len(ips) == 0 {
				break
			}
			nextIP, nextName = ips[0], nsNames[0]
		}

		server = net.JoinHostPort(nextIP, "53")
		serverName = nextName
	}

	return steps, nil
}

// checkDelegation runs the iterative trace and renders each step as one
// line of multi-line hint output.
func (d *diagnosis) checkDelegation() Check {
	c := Check{Name: "Delegation"}
	if !d.resolved {
		c.Status = StatusSkip
		c.Summary = "skipped — DNS did not resolve"
		return c
	}

	steps, err := traceDelegation(d.host, d.timeout)
	if len(steps) == 0 {
		c.Status = StatusWarn
		c.Summary = "delegation trace failed"
		if err != nil {
			c.Detail = map[string]any{"error": tidyErr(err)}
		}
		return c
	}

	c.Detail = map[string]any{"steps": steps}
	c.Status = StatusOK
	c.Summary = fmt.Sprintf("walked %d level%s from root to authoritative", len(steps), plural(len(steps)))

	var lines []string
	for _, s := range steps {
		zone := s.Zone
		if zone == "" {
			zone = "."
		}
		marker := "→"
		if s.Authoritative {
			marker = "★"
		}
		lines = append(lines, fmt.Sprintf("%s  %-20s  via %s", marker, truncate(zone, 18), s.ServerName))
	}
	c.Hint = strings.Join(lines, "\n")

	return c
}
