//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Linux IP_RECVERR-based TCP-source-port ECMP traceroute. Unprivileged.
//
// Design:
//
//   For each (source-port family, TTL) cell:
//     1. Open AF_INET SOCK_STREAM IPPROTO_TCP socket with O_NONBLOCK
//     2. Set IP_TTL to the cell's TTL
//     3. Set IP_RECVERR to enable async error reporting via error queue
//     4. SO_REUSEADDR so rapid re-runs don't trip TIME_WAIT
//     5. Bind to a fixed source port unique to this cell
//     6. connect(target, dstPort) — non-blocking, returns EINPROGRESS
//     7. poll(POLLOUT|POLLERR) up to per-probe timeout
//     8. getsockopt(SO_ERROR):
//          - 0 → SYN-ACK received, destination reached
//          - ECONNREFUSED → RST received, destination reached (port closed)
//          - other → connect failed; ICMP details (if any) in error queue
//     9. recvmsg(MSG_ERRQUEUE) returns cmsg of type IP_RECVERR carrying
//        sock_extended_err + offender sockaddr_in (the router IP)
//
// The 5 source-port families are spread across distinct port ranges so
// each (family, TTL) cell has a unique source port. After all probes
// complete we count distinct path signatures across families.
//
// Per-cell socket lifetime is short — open, probe, parse, close. The
// kernel's per-socket error queue means we never confuse cells with
// each other. No global ICMP listener, no quoted-packet correlation:
// the kernel does the demux for us.

// Linux IP_RECVERR ancillary-data layout. From <linux/errqueue.h>:
//
//	struct sock_extended_err {
//	    __u32 ee_errno;     /* error number */
//	    __u8  ee_origin;    /* where the error originated */
//	    __u8  ee_type;      /* type */
//	    __u8  ee_code;      /* code */
//	    __u8  ee_pad;
//	    __u32 ee_info;
//	    __u32 ee_data;
//	};
//	#define SO_EE_OFFENDER(ee) ((struct sockaddr *)((ee)+1))
//
// Total sock_extended_err = 16 bytes. Offender sockaddr_in follows
// immediately at offset 16: sin_family(2) + sin_port(2) + sin_addr(4)
// + sin_zero(8) = 16 bytes.
const (
	sockExtErrSize   = 16
	soEEOriginICMP   = 2 // SO_EE_ORIGIN_ICMP from <linux/errqueue.h>
	icmpTimeExceeded = 11
)

// tcpSourcePortTraceSupported is the Linux-side affirmation that the
// IP_RECVERR socket-error-queue technique is available.
func tcpSourcePortTraceSupported() bool { return true }

// probeIPv4ECMPTCPImpl fires 5×maxHops parallel SYN probes, demuxed by
// the kernel's per-socket error queue, and aggregates results into per-
// source-port paths.
func probeIPv4ECMPTCPImpl(target net.IP, dstPort, maxHops int, timeout time.Duration) tcpECMPResult {
	out := tcpECMPResult{Attempted: true, DstPort: dstPort}

	if maxHops <= 0 {
		maxHops = 30
	}

	const numFamilies = 5
	const basePort = 33434 // classical traceroute UDP port range (RFC 4727 reserves 33434-33464)

	// Each cell gets a unique source port: basePort + family*maxHops + (ttl-1)
	// With maxHops=30 and 5 families, ports 33434..33583 — well within the
	// system ephemeral range without colliding with privileged ports.
	out.PortsProbed = numFamilies

	// Per-probe timeout. Keep this brisk — 150 SYNs in flight at once.
	perProbe := timeout
	if perProbe > 3*time.Second {
		perProbe = 3 * time.Second
	}
	if perProbe < 500*time.Millisecond {
		perProbe = 500 * time.Millisecond
	}

	paths := make([][]hopResult, numFamilies)
	for i := range paths {
		paths[i] = make([]hopResult, maxHops)
	}

	var wg sync.WaitGroup
	for fam := 0; fam < numFamilies; fam++ {
		for ttl := 1; ttl <= maxHops; ttl++ {
			srcPort := basePort + fam*maxHops + (ttl - 1)
			wg.Add(1)
			go func(fam, ttl, srcPort int) {
				defer wg.Done()
				h := tcpProbeCell(target, dstPort, srcPort, ttl, perProbe)
				h.TTL = ttl
				paths[fam][ttl-1] = h
			}(fam, ttl, srcPort)
		}
	}
	wg.Wait()

	// Trim each path to its first reached-destination hop so unrelated
	// post-destination probes don't pollute the signature.
	for fam := 0; fam < numFamilies; fam++ {
		final := len(paths[fam])
		for i, h := range paths[fam] {
			if h.Reached {
				final = i + 1
				break
			}
		}
		paths[fam] = paths[fam][:final]
	}

	// Concurrent reverse-DNS for unique hop IPs across all families.
	unique := make(map[string]struct{})
	for _, p := range paths {
		for _, h := range p {
			if h.IP != "" {
				unique[h.IP] = struct{}{}
			}
		}
	}
	names := make(map[string]string, len(unique))
	var nameMu sync.Mutex
	var nameWG sync.WaitGroup
	for ip := range unique {
		nameWG.Add(1)
		go func(ip string) {
			defer nameWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if n, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(n) > 0 {
				nameMu.Lock()
				names[ip] = strings.TrimSuffix(n[0], ".")
				nameMu.Unlock()
			}
		}(ip)
	}
	nameWG.Wait()
	for fam := range paths {
		for i := range paths[fam] {
			if n, ok := names[paths[fam][i].IP]; ok {
				paths[fam][i].Name = n
			}
		}
	}

	out.Paths = paths

	// Distinct path signatures — concatenated hop IPs after trim, sorted
	// so the signature is order-invariant within a single family path.
	// We DON'T sort across the path because hop order matters for ECMP;
	// we want to detect "same hops in same order" vs "different hops".
	sigs := make(map[string]struct{})
	for _, p := range paths {
		var ips []string
		for _, h := range p {
			if h.IP != "" {
				ips = append(ips, h.IP)
			}
		}
		sigs[strings.Join(ips, ",")] = struct{}{}
	}
	out.DistinctPaths = len(sigs)
	if out.DistinctPaths == 0 {
		// All probes silent — no reachable hops at all (firewall dropping
		// outbound SYN, ISP blocks, etc.). Don't claim ECMP visibility.
		out.DistinctPaths = 0
		out.ECMPVisible = false
	} else {
		out.ECMPVisible = out.DistinctPaths >= 2
	}
	return out
}

// tcpProbeCell fires one (srcPort, TTL) SYN and waits for either:
//   - SYN-ACK / RST from destination (we reached it)
//   - ICMP Time Exceeded from an intermediate router (delivered via
//     IP_RECVERR socket error queue)
//   - timeout
//
// Returns the responding hop's IP (empty if silent), RTT, and Reached
// flag. The returned hopResult does not include TTL; caller fills it in.
func tcpProbeCell(target net.IP, dstPort, srcPort, ttl int, timeout time.Duration) hopResult {
	var h hopResult

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return h
	}
	defer unix.Close(fd)

	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		return h
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return h
	}

	// Bind to our chosen source port. INADDR_ANY for the address —
	// the kernel picks the right outgoing interface based on routing.
	lsa := &unix.SockaddrInet4{Port: srcPort}
	if err := unix.Bind(fd, lsa); err != nil {
		// Port collision (TIME_WAIT despite REUSEADDR, or another local
		// listener); skip this cell. Empty hopResult signals "no data".
		return h
	}

	dsa := &unix.SockaddrInet4{Port: dstPort}
	copy(dsa.Addr[:], target.To4())

	start := time.Now()
	connectErr := unix.Connect(fd, dsa)
	// Non-blocking connect almost always returns EINPROGRESS. If it
	// returns immediately with another error (e.g., synchronous local
	// failure), there may already be an ICMP-derived error on the queue.
	if connectErr != nil && connectErr != unix.EINPROGRESS && connectErr != unix.EAGAIN {
		if h2, ok := drainErrorQueue(fd, time.Since(start)); ok {
			return h2
		}
		return h
	}

	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT | unix.POLLERR}}
	pollTimeoutMs := int(timeout / time.Millisecond)
	if pollTimeoutMs < 1 {
		pollTimeoutMs = 1
	}
	pn, perr := unix.Poll(pfd, pollTimeoutMs)
	rtt := time.Since(start)
	if perr != nil || pn == 0 {
		// Timed out or interrupted — try error queue one last time, in
		// case ICMP arrived just before the timeout fired.
		if h2, ok := drainErrorQueue(fd, rtt); ok {
			return h2
		}
		return h
	}

	// poll returned with an event. Check SO_ERROR to find out why.
	soErr, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if soErr == 0 {
		// SYN-ACK received from destination.
		h.IP = target.String()
		h.rtt = rtt
		h.RTTms = ms(rtt)
		h.Reached = true
		return h
	}
	// ECONNREFUSED = RST from destination → reachable, port closed.
	// Also count as "reached" — we made round-trip contact.
	if syscall.Errno(soErr) == unix.ECONNREFUSED {
		h.IP = target.String()
		h.rtt = rtt
		h.RTTms = ms(rtt)
		h.Reached = true
		return h
	}
	// Other connect failure — usually ICMP-derived (TTL expired in
	// transit, host unreachable). Drain the error queue.
	if h2, ok := drainErrorQueue(fd, rtt); ok {
		return h2
	}
	return h
}

// drainErrorQueue reads one MSG_ERRQUEUE message and parses any
// IP_RECVERR ancillary data carrying ICMP details. Returns the hop with
// IP/RTT set when an ICMP-originated error is found, or ok=false otherwise.
func drainErrorQueue(fd int, rtt time.Duration) (hopResult, bool) {
	var h hopResult
	buf := make([]byte, 256)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil || oobn == 0 {
		return h, false
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return h, false
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
		//   7 ee_pad, 8-11 ee_info (u32), 12-15 ee_data (u32).
		origin := m.Data[4]
		if origin != soEEOriginICMP {
			continue
		}
		// Offender sockaddr_in begins at offset 16:
		//   16-17 sin_family (u16 host-byte-order, AF_INET=2)
		//   18-19 sin_port
		//   20-23 sin_addr (net-byte-order octets)
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
		return h, true
	}
	return h, false
}

