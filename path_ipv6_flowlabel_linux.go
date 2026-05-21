//go:build linux

package main

import (
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux IPv6 flow-label control. The kernel exposes flow-label management
// via TWO setsockopts:
//
//   1. IPV6_FLOWLABEL_MGR — reserve a specific 20-bit flow label for the
//      socket via an in6_flowlabel_req struct (sock_in6.c kernel impl).
//      Linux 3.7+ supports IPV6_FL_S_ANY share-mode = unprivileged.
//
//   2. IPV6_FLOWINFO_SEND — enable inclusion of flow info in outgoing
//      packets; without this the reserved label is ignored.
//
// Together these let us set arbitrary 20-bit flow labels on unprivileged
// SOCK_DGRAM ICMPv6 sockets — exactly what we need for ECMP discovery
// without raw-socket access.
//
// References:
//   net/ipv6/sockopt_in6.c in the Linux kernel
//   man 7 ipv6 — section "Flow labels"
//   include/uapi/linux/in6.h — struct in6_flowlabel_req

// Constants from <linux/in6.h>. Not exported by golang.org/x/sys/unix
// as of the version in this module, so we declare them explicitly.
const (
	ipv6FlowLabelMgr  = 32 // IPV6_FLOWLABEL_MGR
	ipv6FlowInfoSend  = 33 // IPV6_FLOWINFO_SEND
	flAGet            = 0  // IPV6_FL_A_GET
	flSAny            = 255 // IPV6_FL_S_ANY (unprivileged)
	flFCreate         = 1  // IPV6_FL_F_CREATE
)

// in6FlowlabelReq mirrors struct in6_flowlabel_req from <linux/in6.h>:
//
//	struct in6_flowlabel_req {
//	    struct in6_addr flr_dst;
//	    __be32          flr_label;
//	    __u8            flr_action;
//	    __u8            flr_share;
//	    __u16           flr_flags;
//	    __u16           flr_expires;
//	    __u16           flr_linger;
//	    __u32           __flr_pad;
//	};
//
// 32 bytes packed, big-endian-on-wire for the label field.
type in6FlowlabelReq struct {
	Dst     [16]byte
	Label   uint32 // network byte order (big-endian, 20 bits)
	Action  uint8
	Share   uint8
	Flags   uint16
	Expires uint16
	Linger  uint16
	Pad     uint32
}

// flowLabelSupported returns true on Linux where IPV6_FLOWLABEL_MGR is
// available. We don't pre-test — the actual setsockopt happens in
// probeIPv6FlowTTL and a failure there returns an empty hop result.
func flowLabelSupported(target net.IP, timeout time.Duration) bool {
	if target.To4() != nil {
		return false
	}
	return true
}

// probeIPv6FlowTTL sends one ICMPv6 echo at the given TTL with the
// specified 20-bit flow label, listens for ICMPv6 Time Exceeded / Echo
// Reply. Returns the responding hop. Linux-only.
func probeIPv6FlowTTL(target net.IP, ttl int, flow uint32, timeout time.Duration) hopResult {
	var h hopResult

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	if err != nil {
		return h
	}
	defer unix.Close(fd)

	// Reserve the flow label for this socket destination.
	var req in6FlowlabelReq
	copy(req.Dst[:], target.To16())
	req.Label = uint32(flow & 0xFFFFF) // 20-bit
	req.Action = flAGet
	req.Share = flSAny
	req.Flags = flFCreate
	// Pass the struct as bytes via SetsockoptString.
	reqBytes := (*[32]byte)(unsafe.Pointer(&req))[:]
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IPV6, ipv6FlowLabelMgr, string(reqBytes)); err != nil {
		return h
	}
	// Enable flow-info send.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, ipv6FlowInfoSend, 1); err != nil {
		return h
	}
	// Set hop limit.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl); err != nil {
		return h
	}
	// Set send/recv timeouts.
	tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int64((timeout % time.Second) / time.Microsecond)}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// Build the destination sockaddr.
	sa := &unix.SockaddrInet6{Port: 0}
	copy(sa.Addr[:], target.To16())

	// Build minimal ICMPv6 Echo Request body.
	pkt := []byte{128, 0, 0, 0, 0, 1, 0, 1} // type 128 echo, code 0, csum 0, id 1, seq 1
	// Flow label comes from IPV6_FLOWLABEL_MGR reservation above —
	// kernel includes it in the outgoing IPv6 header when IPV6_FLOWINFO_SEND
	// is set.

	start := time.Now()
	if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
		return h
	}
	buf := make([]byte, 1500)
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil || n < 4 {
		return h
	}
	src, ok := from.(*unix.SockaddrInet6)
	if !ok {
		return h
	}
	h.IP = net.IP(src.Addr[:]).String()
	h.rtt = time.Since(start)
	h.RTTms = ms(h.rtt)
	if buf[0] == 129 {
		h.Reached = true
	}
	return h
}
