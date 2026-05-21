//go:build windows

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// Real ICMP echo on Windows via iphlpapi.IcmpSendEcho. This API does the
// kernel work for us — no raw sockets, no admin privilege needed.

var (
	iphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho     = iphlpapi.NewProc("IcmpSendEcho")
	procIcmp6CreateFile  = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmp6SendEcho2   = iphlpapi.NewProc("Icmp6SendEcho2")
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION from <ipexport.h>.
// On 64-bit Windows it is 16 bytes — Go inserts the 4-byte padding
// between OptionsSize and OptionsData automatically.
type ipOptionInformation struct {
	Ttl         byte
	Tos         byte
	Flags       byte
	OptionsSize byte
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY from <ipexport.h>. Total size is
// 40 bytes on 64-bit Windows; Go's natural alignment matches.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// IP_FLAG_DF is the IP_OPTION_INFORMATION.Flags bit that sets the
// don't-fragment flag on the outgoing IP packet. Used by Path-MTU detection.
const IP_FLAG_DF = 0x02

// Windows IP_STATUS values surfaced when DF probes meet a smaller-MTU link.
const (
	IP_PACKET_TOO_BIG = 11009 // ICMP frag-needed received from intermediate router
	IP_REQ_TIMED_OUT  = 11010
)

// pingICMPSized sends an ICMP echo with a caller-chosen payload size and
// optional don't-fragment flag, returning the raw IP_STATUS plus RTT. It is
// the substrate for Path-MTU detection: incrementally larger payloads with
// DF set find the largest packet that traverses the path without fragmenting.
//
// Status 0 (IP_SUCCESS) → fits. Status 11009 (IP_PACKET_TOO_BIG) → too big,
// router replied with ICMP frag-needed. Other statuses or err → silent drop,
// also treated as "too big" by the MTU detector since some routers drop DF
// packets without sending the canonical ICMP response.
func pingICMPSized(dest net.IP, payloadSize int, dontFragment bool, timeout time.Duration) (uint32, time.Duration, error) {
	v4 := dest.To4()
	if v4 == nil {
		return 0, 0, fmt.Errorf("icmp: only IPv4 supported in this iteration")
	}
	if payloadSize < 1 {
		payloadSize = 1
	}
	if payloadSize > 65500 {
		payloadSize = 65500
	}

	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, 0, fmt.Errorf("icmp: IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(h)

	ipAddr := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24

	reqData := make([]byte, payloadSize)
	// Reply buffer = ICMP_ECHO_REPLY (40 B) + echoed payload + slack.
	replySize := payloadSize + 256
	replyBuf := make([]byte, replySize)

	// Ttl=0 in IP_OPTION_INFORMATION is taken literally by IcmpSendEcho —
	// the first hop returns TTL_EXPIRED_TRANSIT instead of forwarding. Set
	// it explicitly. The pingICMP path passes NULL options to get the
	// stack default; we need a struct because we want to set Flags.
	opts := ipOptionInformation{Ttl: 128}
	if dontFragment {
		opts.Flags = IP_FLAG_DF
	}

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
		return 0, 0, fmt.Errorf("icmp: no reply")
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	return reply.Status, time.Duration(reply.RoundTripTime) * time.Millisecond, nil
}

// pingICMP sends a single ICMP echo to dest and returns the round-trip time.
// Only IPv4 is supported in this iteration; IPv6 echo would use Icmp6SendEcho2.
func pingICMP(dest net.IP, timeout time.Duration) (time.Duration, error) {
	v4 := dest.To4()
	if v4 == nil {
		return 0, fmt.Errorf("icmp: only IPv4 supported in this iteration")
	}

	h, _, _ := procIcmpCreateFile.Call()
	// IcmpCreateFile returns INVALID_HANDLE_VALUE (~0) on error.
	if h == 0 || h == ^uintptr(0) {
		return 0, fmt.Errorf("icmp: IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(h)

	// IPAddr is a DWORD holding the v4 octets in network byte order, which
	// on little-endian x64 means octet 0 in the lowest byte.
	ipAddr := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24

	// Small request payload — 8 bytes of arbitrary data.
	reqData := []byte{'n', 'e', 't', 'd', 'o', 'c', 0, 0}

	// Reply buffer needs to fit one ICMP_ECHO_REPLY plus the request data;
	// 256 bytes is comfortably more than required.
	replyBuf := make([]byte, 256)

	// IcmpSendEcho returns the number of replies received (0 = timeout/error).
	ret, _, _ := procIcmpSendEcho.Call(
		h,
		uintptr(ipAddr),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		0, // RequestOptions: NULL → default TTL / no options
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeout.Milliseconds()),
	)
	if ret == 0 {
		return 0, fmt.Errorf("icmp: no reply")
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 {
		return 0, fmt.Errorf("icmp: status %d", reply.Status)
	}
	return time.Duration(reply.RoundTripTime) * time.Millisecond, nil
}
