package main

import (
	"net"
	"strconv"
	"time"
)

// UDP port scanning + service-ID dispatcher.
//
// UDP is fundamentally harder to scan than TCP because there's no
// connection-oriented response. The classification taxonomy nmap -sU uses:
//
//   open            — got an app-layer UDP response (e.g., NTP, DNS)
//   closed          — got ICMP Port Unreachable (type 3 code 3)
//   filtered        — no response of any kind (silent drop, often a firewall)
//   open|filtered   — fallback when ICMP receive isn't available
//
// Receiving ICMP errors for UDP unprivileged is only possible on Linux via
// IP_RECVERR — same scaffolding the TCP-source-port traceroute uses.
// On macOS / Windows / BSDs we degrade to "got response or didn't" without
// the closed-vs-filtered distinction.
//
// Active service probes for UDP ports (NTP at 123, DNS server.bind at 53)
// live in their own files (service_ntp.go, service_dns_udp.go) and follow
// the same contract as TCP service probes: (addr, host, timeout) → serviceInfo.
//
// scanUDPPort orchestrates: fire the registered probe (which sends its own
// UDP payload and reads the response) AND in parallel (on Linux) ask the
// classifier whether an ICMP Port Unreachable arrived during the same
// window. The classifier's result is merged into portResult as UDPState.

// scanUDPPort runs a UDP-aware probe + classification for one port.
// Mutates the supplied portResult in place — adds UDP-specific fields
// when the probe responds or when the classifier observes ICMP.
func scanUDPPort(r *portResult, target net.IP, port int) {
	probe, ok := udpServicePortMap[port]
	if !ok {
		// No registered UDP probe; fall back to a no-op classifier-only run.
		// We don't blindly send UDP scans for arbitrary ports because UDP
		// scanning without a port-specific payload is uninformative — most
		// servers ignore unsolicited UDP and the scanner can't differentiate
		// open-and-silent from filtered-by-firewall.
		return
	}

	addr := net.JoinHostPort(target.String(), strconv.Itoa(port))
	timeout := 1500 * time.Millisecond

	// Run the app-layer probe AND the classifier concurrently. The probe
	// drives its own UDP socket (DialTimeout("udp", ...)) so we don't share
	// state with the classifier. The classifier opens its own SOCK_DGRAM
	// UDP socket with IP_RECVERR enabled and sends the same payload as the
	// probe to get the kernel to deliver any ICMP error.
	//
	// In practice both fire similar payloads; doing them in parallel keeps
	// the wall clock to one timeout window.
	probeDone := make(chan serviceInfo, 1)
	classifyDone := make(chan udpClassification, 1)
	go func() {
		probeDone <- probe(addr, target.String(), timeout)
	}()
	go func() {
		classifyDone <- classifyUDPPort(target, port, probeUDPPayload(port), timeout)
	}()

	info := <-probeDone
	cls := <-classifyDone

	// UDPState is independent of r.Open (which is TCP-specific). A port
	// can be TCP-closed and UDP-open at the same time (e.g., 123 — NTP
	// never runs on TCP). We never set r.Open here; the upstream TCP
	// scanner owns that flag.
	//
	// UDP probes follow the convention that a non-empty Product means
	// "I confirmed an app-layer response of this protocol." Both
	// probeNTP and probeDNSUDP return zero-value serviceInfo on no-
	// response / unparseable-response, so Product is reliable evidence.
	if info.Product != "" {
		r.UDPState = "open"
		// Promote product/version/banner only when the TCP scan didn't
		// already fill them — TCP service info wins when both transports
		// respond on the same port (e.g., 53 with TCP AXFR + UDP queries).
		if r.Product == "" && info.Product != "" {
			r.Product = info.Product
		}
		if r.Version == "" && info.Version != "" {
			r.Version = info.Version
		}
		if r.Banner == "" && info.Banner != "" {
			r.Banner = info.Banner
		}
		if r.Extra == nil {
			r.Extra = map[string]string{}
		}
		for k, v := range info.Extra {
			if _, exists := r.Extra[k]; !exists {
				r.Extra[k] = v
			}
		}
		// Only override Service to the UDP variant if the TCP scan
		// didn't populate it with a TCP-specific service name.
		if r.Service == "" || r.Service == "?" {
			r.Service = serviceNameUDP(port)
		}
		return
	}

	// App-layer probe found nothing to fingerprint. Use the classifier's
	// kernel-level verdict if available.
	switch cls.state {
	case "open":
		// Classifier saw POLLIN on its own socket (a UDP datagram came
		// back) but the app-layer probe couldn't parse it. Port is open
		// but the response was unfingerprintable — still useful signal.
		r.UDPState = "open"
		r.Service = serviceNameUDP(port)
		if info.Product != "" {
			// Promote the bare protocol label so the user sees "ntp" not "?"
			r.Product = info.Product
		}
	case "closed":
		r.UDPState = "closed"
		r.Service = serviceNameUDP(port)
	case "filtered":
		r.UDPState = "filtered"
		r.Service = serviceNameUDP(port)
	case "open|filtered":
		// Non-Linux fallback when ICMP receive isn't available.
		r.UDPState = "open|filtered"
		r.Service = serviceNameUDP(port)
	default:
		// Empty state — classifier couldn't determine anything. Leave
		// UDPState unset so the dispatcher upstream knows there's no
		// signal worth surfacing.
	}
}

// udpClassification is the per-port verdict from classifyUDPPort.
type udpClassification struct {
	state  string // "open", "closed", "filtered", "open|filtered"
	source string // "icmp", "timeout", "platform"
}

// probeUDPPayload returns a port-appropriate UDP payload that's likely to
// elicit either an app-layer response (from an open port) or an ICMP Port
// Unreachable (from a closed port). For ports without a known payload, we
// send a small generic byte sequence — many UDP services ignore garbage,
// which is fine because we're looking for the ICMP error signal anyway.
func probeUDPPayload(port int) []byte {
	switch port {
	case 53:
		// Minimal DNS query for "version.bind" CH TXT — most BIND/Unbound
		// instances respond, and even closed ports trigger ICMP.
		return dnsCHAOSWireProbe("version.bind.")
	case 123:
		// NTP control mode-6 readvar (mirrors service_ntp.go's request).
		return []byte{0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	case 161:
		// SNMPv2c GetRequest for sysDescr.0.
		// 30 26 02 01 01 (SEQUENCE len 38, INTEGER 1=v2c) ...
		return []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x71, 0xb4, 0xb5, 0x68, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	default:
		return []byte{0x00}
	}
}

// dnsCHAOSWireProbe builds a minimal wire-format DNS query for the given
// CH-class TXT name. Used to elicit a response (or an ICMP error) from a
// candidate DNS server. The query is enough to trigger BIND/Unbound to
// answer with their version string when they accept CHAOS-class queries.
func dnsCHAOSWireProbe(name string) []byte {
	// 12-byte header: id=0xCAFE, flags=0x0100 (standard query, RD=1),
	// QDCOUNT=1, ANCOUNT=ARCOUNT=NSCOUNT=0
	pkt := []byte{0xCA, 0xFE, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// QNAME — labels of name (terminated with 0)
	for _, lbl := range splitDNSLabels(name) {
		if len(lbl) == 0 {
			break
		}
		if len(lbl) > 63 {
			lbl = lbl[:63]
		}
		pkt = append(pkt, byte(len(lbl)))
		pkt = append(pkt, []byte(lbl)...)
	}
	pkt = append(pkt, 0x00)
	// QTYPE = TXT (16)
	pkt = append(pkt, 0x00, 0x10)
	// QCLASS = CH (3)
	pkt = append(pkt, 0x00, 0x03)
	return pkt
}

// splitDNSLabels splits a fully-qualified name into wire labels, dropping
// the trailing empty label.
func splitDNSLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, name[start:])
	}
	return out
}

// serviceNameUDP returns the IANA name for UDP ports we care about,
// labelled "(udp)" so the user sees the transport explicitly. Falls
// through to the TCP-name version of serviceName for unlisted ports.
func serviceNameUDP(port int) string {
	switch port {
	case 53:
		return "dns (udp)"
	case 123:
		return "ntp (udp)"
	case 161:
		return "snmp (udp)"
	case 500:
		return "isakmp (udp)"
	case 1900:
		return "ssdp (udp)"
	case 5353:
		return "mdns (udp)"
	}
	return serviceName(port) + " (udp)"
}
