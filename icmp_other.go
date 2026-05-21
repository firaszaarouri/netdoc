//go:build !windows && !linux && !darwin

package main

import (
	"fmt"
	"net"
	"time"
)

// pingICMP on non-Windows platforms currently returns an error so the Latency
// check falls back to its TCP-connect path. A native SOCK_DGRAM ICMP
// implementation for Linux (requires net.ipv4.ping_group_range) and macOS
// (works for non-root by default) is the next item on the roadmap.
func pingICMP(_ net.IP, _ time.Duration) (time.Duration, error) {
	return 0, fmt.Errorf("icmp: native echo not yet implemented on this platform — falling back to TCP")
}

// pingICMPSized stub — Path-MTU detection rides on the same native ICMP path
// that pingICMP does, so it shares the cross-platform gap. Returns the same
// "not implemented" sentinel so the Path-MTU detector can skip silently.
func pingICMPSized(_ net.IP, _ int, _ bool, _ time.Duration) (uint32, time.Duration, error) {
	return 0, 0, fmt.Errorf("icmp: native echo not yet implemented on this platform")
}
