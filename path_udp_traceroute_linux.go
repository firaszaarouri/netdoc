//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Linux IP_RECVERR-based UDP traceroute. Unprivileged.
//
// Per-TTL cell:
//
//	1. AF_INET SOCK_DGRAM IPPROTO_UDP with O_NONBLOCK | CLOEXEC
//	2. IP_TTL = ttl
//	3. IP_RECVERR = 1
//	4. connect() to (target, basePort + ttl - 1) — kernel routes ICMP
//	   errors for this 4-tuple to OUR socket's error queue
//	5. write() one byte of UDP payload
//	6. poll(POLLERR | POLLIN, timeout)
//	7. drain MSG_ERRQUEUE — IP_RECVERR cmsg carries sock_extended_err
//	   + offender sockaddr_in (the responding hop's IP):
//	      ee_type=11 (Time Exceeded)  → intermediate hop
//	      ee_type=3 code=3 (Port Unreachable) → reached destination
//	8. If POLLIN fires instead (rare — a listener was actually at that
//	   port), classify as reached.
//
// We use a fresh per-TTL destination port (basePort + ttl - 1, 33834..)
// so that ICMP Port Unreachable from the destination is attributable to
// a specific TTL. Per-socket error queue + per-TTL destination port
// together give crisp, demuxed results without any quoted-packet parsing.

const udpTraceBasePort = 33834

func udpTracerouteSupported() bool { return true }

func probeIPv4UDPTracerouteImpl(target net.IP, maxHops int, timeout time.Duration) udpTraceResult {
	out := udpTraceResult{Attempted: true}
	if maxHops <= 0 {
		maxHops = 30
	}

	// Per-probe timeout. Cap brisk; we fire 30 in parallel.
	perProbe := timeout
	if perProbe > 2*time.Second {
		perProbe = 2 * time.Second
	}
	if perProbe < 500*time.Millisecond {
		perProbe = 500 * time.Millisecond
	}

	hops := make([]hopResult, maxHops)

	var wg sync.WaitGroup
	for ttl := 1; ttl <= maxHops; ttl++ {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			dstPort := udpTraceBasePort + (ttl - 1)
			h := udpProbeCell(target, dstPort, ttl, perProbe)
			h.TTL = ttl
			hops[ttl-1] = h
		}(ttl)
	}
	wg.Wait()

	// Trim to first reached hop — TTLs beyond destination would just
	// reach destination again and bloat the path.
	final := maxHops
	for i, h := range hops {
		if h.Reached {
			final = i + 1
			break
		}
	}
	hops = hops[:final]
	out.Hops = hops

	// Was destination reached?
	for _, h := range hops {
		if h.Reached {
			out.Reached = true
			break
		}
	}

	// Concurrent reverse-DNS for hop IPs.
	var nameWG sync.WaitGroup
	for i := range hops {
		if hops[i].IP == "" {
			continue
		}
		nameWG.Add(1)
		go func(idx int) {
			defer nameWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(ctx, hops[idx].IP); err == nil && len(names) > 0 {
				hops[idx].Name = strings.TrimSuffix(names[0], ".")
			}
		}(i)
	}
	nameWG.Wait()

	return out
}

// udpProbeCell fires one UDP probe at the given TTL/destination-port and
// waits for either ICMP Time Exceeded (intermediate hop) or ICMP Port
// Unreachable (destination reached). Returns the responding hop's IP +
// RTT, or empty hopResult on silent timeout.
func udpProbeCell(target net.IP, dstPort, ttl int, timeout time.Duration) hopResult {
	var h hopResult

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return h
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		return h
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return h
	}

	// connect() the UDP socket so the kernel demuxes ICMP errors for
	// (target, dstPort) → this socket specifically.
	sa := &unix.SockaddrInet4{Port: dstPort}
	copy(sa.Addr[:], target.To4())
	if err := unix.Connect(fd, sa); err != nil {
		return h
	}

	// One byte of probe payload is enough — we only need the kernel to
	// emit the UDP datagram so routers respond with Time Exceeded as the
	// TTL counts down.
	start := time.Now()
	if _, err := unix.Write(fd, []byte{0x00}); err != nil {
		// Synchronous failure → check error queue immediately.
		return drainUDPTraceErrQueue(fd, time.Since(start))
	}

	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
	pollMs := int(timeout / time.Millisecond)
	if pollMs < 1 {
		pollMs = 1
	}
	n, perr := unix.Poll(pfd, pollMs)
	rtt := time.Since(start)
	if perr != nil || n == 0 {
		// Timeout — last-chance drain.
		return drainUDPTraceErrQueue(fd, rtt)
	}

	// POLLIN: app-layer response on UDP socket → destination has a
	// listener at this port (rare, since we pick high random ports).
	// Count as "reached".
	if pfd[0].Revents&unix.POLLIN != 0 {
		h.IP = target.String()
		h.rtt = rtt
		h.RTTms = ms(rtt)
		h.Reached = true
		return h
	}

	// POLLERR: ICMP error queued.
	return drainUDPTraceErrQueue(fd, rtt)
}

// drainUDPTraceErrQueue reads one MSG_ERRQUEUE message, parses the
// IP_RECVERR ancillary data, and extracts (offender IP, reached?). The
// "reached" flag is set when the ICMP error is type=3 code=3 (Port
// Unreachable) — i.e., the destination itself sent the error.
func drainUDPTraceErrQueue(fd int, rtt time.Duration) hopResult {
	var h hopResult
	buf := make([]byte, 256)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil || oobn == 0 {
		return h
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return h
	}
	for _, m := range cmsgs {
		if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_RECVERR {
			continue
		}
		if len(m.Data) < sockExtErrSize+8 {
			continue
		}
		// sock_extended_err layout (16 bytes):
		//   0-3 ee_errno (u32), 4 ee_origin, 5 ee_type, 6 ee_code,
		//   7 ee_pad, 8-11 ee_info, 12-15 ee_data
		origin := m.Data[4]
		eeType := m.Data[5]
		eeCode := m.Data[6]
		if origin != soEEOriginICMP {
			continue
		}
		// Offender sockaddr_in begins at offset 16. Bytes 20-23 = IP.
		if len(m.Data) < 24 {
			continue
		}
		family := binary.LittleEndian.Uint16(m.Data[16:18])
		if family != unix.AF_INET {
			continue
		}
		ip := net.IPv4(m.Data[20], m.Data[21], m.Data[22], m.Data[23])
		h.IP = ip.String()
		h.rtt = rtt
		h.RTTms = ms(rtt)
		// type=3 (Destination Unreachable) code=3 (Port Unreachable)
		// means the offender IS the destination — we reached it. Any
		// other type=3 code (host/net unreachable) is an upstream block,
		// not a "reached" signal.
		if eeType == 3 && eeCode == 3 {
			h.Reached = true
		}
		// type=11 (Time Exceeded) is the normal mid-path response — not
		// a reached signal, just a hop attribution.
		return h
	}
	return h
}
