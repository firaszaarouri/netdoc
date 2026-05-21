//go:build linux || darwin

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Native ICMP echo on Linux + macOS via SOCK_DGRAM ICMP sockets — no raw
// sockets, no setuid binary, no root. Works for non-root by default on:
//   - macOS (since OS X 10.5; built into the kernel)
//   - Linux (when the kernel's net.ipv4.ping_group_range covers the user's
//     primary GID; default on Ubuntu/Debian/Fedora/Arch since 2014)
//
// When the kernel says "permission denied" (Linux without ping_group_range)
// the listener fails up front and the Latency check falls back to TCP-
// connect probes, identical to the previous "not yet implemented" path.

const protocolICMP = 1 // IANA protocol number for ICMPv4

// pingICMP sends one ICMP Echo Request to dest and returns the round-trip
// time. IPv4-only in this iteration; ICMPv6 (golang.org/x/net/ipv6) is a
// drop-in extension that can be added the same way.
func pingICMP(dest net.IP, timeout time.Duration) (time.Duration, error) {
	v4 := dest.To4()
	if v4 == nil {
		return 0, fmt.Errorf("icmp: only IPv4 supported in this iteration")
	}

	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, fmt.Errorf("icmp: ListenPacket (Linux: check net.ipv4.ping_group_range): %w", err)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("netdoc"),
		},
	}
	wireBuf, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := conn.WriteTo(wireBuf, &net.UDPAddr{IP: dest}); err != nil {
		return 0, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)

	rm, err := icmp.ParseMessage(protocolICMP, reply[:n])
	if err != nil {
		return 0, err
	}
	if rm.Type != ipv4.ICMPTypeEchoReply {
		return 0, fmt.Errorf("icmp: unexpected reply type %v", rm.Type)
	}
	return rtt, nil
}

// pingICMPWithTTL sends an ICMP Echo with the given TTL. Intermediate routers
// that decrement the TTL to zero reply with ICMP Time Exceeded; their IP is
// in the response. The destination itself replies with Echo Reply.
func pingICMPWithTTL(dest net.IP, ttl int, timeout time.Duration) (net.IP, time.Duration, bool, error) {
	v4 := dest.To4()
	if v4 == nil {
		return nil, 0, false, fmt.Errorf("traceroute: only IPv4 supported in this iteration")
	}

	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, 0, false, err
	}
	defer conn.Close()

	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return nil, 0, false, err
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  ttl, // sequence = ttl makes per-hop replies easy to identify
			Data: []byte("netdoc"),
		},
	}
	wireBuf, err := msg.Marshal(nil)
	if err != nil {
		return nil, 0, false, err
	}
	start := time.Now()
	if _, err := conn.WriteTo(wireBuf, &net.UDPAddr{IP: dest}); err != nil {
		return nil, 0, false, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return nil, 0, false, err
	}
	rtt := time.Since(start)

	peerIP := net.IP(nil)
	if udpAddr, ok := peer.(*net.UDPAddr); ok {
		peerIP = udpAddr.IP
	}

	rm, err := icmp.ParseMessage(protocolICMP, reply[:n])
	if err != nil {
		return peerIP, rtt, false, err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return peerIP, rtt, true, nil
	case ipv4.ICMPTypeTimeExceeded:
		return peerIP, rtt, false, nil
	default:
		return peerIP, rtt, false, fmt.Errorf("traceroute: unexpected reply type %v", rm.Type)
	}
}

// pingICMPSized stub on Linux/macOS — Path-MTU detection requires the
// don't-fragment IP option which SOCK_DGRAM ICMP doesn't easily expose
// through golang.org/x/net/ipv4 (would need raw socket privileges). Returns
// the same not-implemented sentinel as the cross-platform stub so the
// MTU detector skips silently.
func pingICMPSized(_ net.IP, _ int, _ bool, _ time.Duration) (uint32, time.Duration, error) {
	return 0, 0, fmt.Errorf("icmp: DF-bit path-MTU detection not yet supported on this platform")
}
