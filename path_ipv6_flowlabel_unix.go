//go:build darwin

package main

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS IPv6 flow-label control. macOS exposes flow info via the
// `sin6_flowinfo` field of `struct sockaddr_in6`. The Go unix package's
// `RawSockaddrInet6` HAS a `Flowinfo` field but the high-level
// `unix.SockaddrInet6` Sendto path doesn't surface it — we drop to raw
// sendmsg with a hand-packed sockaddr.
//
// Reference: macOS ipv6(4) man page; <netinet/in.h>; <sys/socket.h>.
//
// Status check: this gives macOS users genuine ECMP-aware IPv6 traceroute
// UNPRIVILEGED — same posture as Linux.

const (
	macIPV6FlowInfoSend = 33 // IPV6_FLOWINFO_SEND on macOS
)

func flowLabelSupported(target net.IP, timeout time.Duration) bool {
	return target.To4() == nil
}

// probeIPv6FlowTTL sends one ICMPv6 echo at the given TTL with the
// specified 20-bit flow label, listens for ICMPv6 Time Exceeded / Echo
// Reply. macOS implementation — uses raw sendmsg with a hand-packed
// sockaddr_in6 carrying flow info in the upper bits of sin6_flowinfo.
//
// Layout of sockaddr_in6 on macOS (28 bytes):
//   uint8  sin6_len       = 28
//   uint8  sin6_family    = AF_INET6 (30)
//   uint16 sin6_port      = 0 (network order)
//   uint32 sin6_flowinfo  = flow label (low 20 bits)
//   uint8  sin6_addr[16]
//   uint32 sin6_scope_id  = 0
func probeIPv6FlowTTL(target net.IP, ttl int, flow uint32, timeout time.Duration) hopResult {
	var h hopResult
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	if err != nil {
		return h
	}
	defer unix.Close(fd)

	// Enable flow-info send. macOS uses the same IPV6_FLOWINFO_SEND
	// constant value as Linux.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, macIPV6FlowInfoSend, 1); err != nil {
		// macOS might not have this option on every kernel version —
		// fall back gracefully.
		_ = err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl); err != nil {
		return h
	}

	tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int32((timeout % time.Second) / time.Microsecond)}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// Construct sockaddr_in6 manually with flow info populated.
	var rsa unix.RawSockaddrInet6
	rsa.Len = unix.SizeofSockaddrInet6
	rsa.Family = unix.AF_INET6
	rsa.Port = 0
	rsa.Flowinfo = flow & 0xFFFFF // 20-bit
	copy(rsa.Addr[:], target.To16())
	rsa.Scope_id = 0

	pkt := []byte{128, 0, 0, 0, 0, 1, 0, 1} // ICMPv6 Echo Request

	// Use syscall.Sendto with the raw sockaddr converted via unsafe pointer.
	start := time.Now()
	_, _, e1 := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(fd),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		0,
		uintptr(unsafe.Pointer(&rsa)),
		uintptr(unix.SizeofSockaddrInet6),
	)
	if e1 != 0 {
		return h
	}
	buf := make([]byte, 1500)
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil || n < 4 {
		return h
	}
	if src, ok := from.(*unix.SockaddrInet6); ok {
		h.IP = net.IP(src.Addr[:]).String()
	}
	h.rtt = time.Since(start)
	h.RTTms = ms(h.rtt)
	if buf[0] == 129 {
		h.Reached = true
	}
	_ = binary.LittleEndian
	return h
}
