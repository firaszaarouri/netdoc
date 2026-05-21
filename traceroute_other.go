//go:build !windows && !linux && !darwin

package main

import (
	"fmt"
	"net"
	"time"
)

// pingICMPWithTTL on the long-tail Unix platforms (FreeBSD, OpenBSD, ...) is
// not yet wired. Linux + macOS use icmp_unix.go (SOCK_DGRAM ICMP via
// golang.org/x/net/icmp). Windows uses iphlpapi.IcmpSendEcho.
func pingICMPWithTTL(_ net.IP, _ int, _ time.Duration) (net.IP, time.Duration, bool, error) {
	return nil, 0, false, fmt.Errorf("traceroute: not yet implemented on this platform")
}
