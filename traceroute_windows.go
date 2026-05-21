//go:build windows

package main

import (
	"fmt"
	"net"
	"time"
	"unsafe"
)

// Windows IP_STATUS values relevant to traceroute responses.
const (
	IP_SUCCESS             = 0
	IP_TTL_EXPIRED_TRANSIT = 11013
)

// pingICMPWithTTL sends a single ICMP echo with the given TTL via
// iphlpapi.IcmpSendEcho. When the TTL is too low to reach the destination,
// the intermediate router that decremented the TTL to zero sends back an
// ICMP Time-Exceeded message, which the API surfaces as IP_TTL_EXPIRED_TRANSIT
// along with the router's IP address — exactly the per-hop data we need.
//
// Returns the responding IP, the round-trip time, and reached == true when
// the destination itself replied (Status == IP_SUCCESS).
func pingICMPWithTTL(dest net.IP, ttl int, timeout time.Duration) (net.IP, time.Duration, bool, error) {
	v4 := dest.To4()
	if v4 == nil {
		return nil, 0, false, fmt.Errorf("traceroute: only IPv4 supported in this iteration")
	}

	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return nil, 0, false, fmt.Errorf("traceroute: IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(h)

	ipAddr := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
	reqData := []byte{'n', 'e', 't', 'd', 'o', 'c', 0, 0}
	replyBuf := make([]byte, 256)
	opts := ipOptionInformation{Ttl: byte(ttl)}

	ret, _, _ := procIcmpSendEcho.Call(
		h,
		uintptr(ipAddr),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeout.Milliseconds()),
	)
	if ret == 0 {
		return nil, 0, false, fmt.Errorf("traceroute: no reply at ttl=%d", ttl)
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	// reply.Address is a DWORD with the IP octets in network byte order;
	// on little-endian x64 octet 1 is the low byte.
	a := reply.Address
	ip := net.IPv4(byte(a&0xFF), byte((a>>8)&0xFF), byte((a>>16)&0xFF), byte((a>>24)&0xFF))
	rtt := time.Duration(reply.RoundTripTime) * time.Millisecond

	switch reply.Status {
	case IP_SUCCESS:
		return ip, rtt, true, nil
	case IP_TTL_EXPIRED_TRANSIT:
		return ip, rtt, false, nil
	default:
		return ip, rtt, false, fmt.Errorf("traceroute: status %d at ttl=%d", reply.Status, ttl)
	}
}
