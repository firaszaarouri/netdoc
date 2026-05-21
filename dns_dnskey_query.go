package main

import (
	"time"

	"github.com/miekg/dns"
)

// queryDNSKEYSet retrieves the full DNSKEY RRset for a zone. Used by the
// algorithm-rollover analysis which needs ALL keys (not just whichever
// signed our leaf answer) to determine if multiple algorithm families
// coexist.
func queryDNSKEYSet(zone string, transport *dnsTransport, timeout time.Duration) []dns.RR {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	rrs, err := queryDNS(zone, dns.TypeDNSKEY, transport, timeout)
	if err != nil {
		return nil
	}
	return rrs
}
