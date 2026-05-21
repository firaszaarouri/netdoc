//go:build linux

package main

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Linux IP_RECVERR-based UDP port classification.
//
// Reuses the IP_RECVERR scaffolding from path_tcp_traceroute_linux.go,
// but for UDP sockets:
//
//   1. Open AF_INET SOCK_DGRAM IPPROTO_UDP with O_NONBLOCK
//   2. Enable IP_RECVERR for async error queue delivery
//   3. connect() the socket to (target, port) — kernel routes only errors
//      for that 4-tuple to this socket's queue
//   4. send the port-appropriate UDP payload
//   5. poll(POLLIN | POLLERR) up to timeout:
//        POLLIN  → UDP response arrived → port is OPEN (handled by the
//                  parallel app-layer probe; we don't need to read here)
//        POLLERR → ICMP error queued; drain it to check origin
//                  ICMP type 3 code 3 (Port Unreachable) → CLOSED
//                  other ICMP → still likely unreachable; treat as CLOSED
//        timeout → no signal → FILTERED
//
// The classifier shares NO state with the app-layer probe — each has its
// own socket. The kernel demuxes responses to the right socket via 4-tuple.

// classifyUDPPort fires a UDP probe and watches for the ICMP error queue.
// Returns the classification verdict. Only Linux delivers ICMP errors
// to userspace via IP_RECVERR; on other platforms classifyUDPPort is
// stubbed in ports_udp_other.go.
func classifyUDPPort(target net.IP, port int, payload []byte, timeout time.Duration) udpClassification {
	v4 := target.To4()
	if v4 == nil {
		return udpClassification{state: "", source: "platform"}
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return udpClassification{state: "open|filtered", source: "platform"}
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return udpClassification{state: "open|filtered", source: "platform"}
	}

	// connect() the UDP socket so the kernel routes ICMP errors for this
	// 4-tuple specifically to our error queue. Without connect(), ICMP
	// errors for the destination might be delivered to ANY UDP socket
	// (and Linux usually drops them entirely without IP_RECVERR).
	sa := &unix.SockaddrInet4{Port: port}
	copy(sa.Addr[:], v4)
	if err := unix.Connect(fd, sa); err != nil {
		return udpClassification{state: "open|filtered", source: "platform"}
	}

	// Send the payload — small (≤ MTU); won't block.
	if _, err := unix.Write(fd, payload); err != nil {
		// Synchronous failure (rare; usually means ICMP came back
		// instantly from a local NAT). Try the error queue anyway.
		if origin, ok := drainUDPErrorQueue(fd); ok {
			if origin == soEEOriginICMP {
				return udpClassification{state: "closed", source: "icmp"}
			}
		}
		return udpClassification{state: "filtered", source: "platform"}
	}

	// Poll for either a UDP response (POLLIN) or an ICMP error (POLLERR).
	// We bound the wait by the same timeout the app-layer probe uses so
	// both finish in lockstep.
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
	pollMs := int(timeout / time.Millisecond)
	if pollMs < 1 {
		pollMs = 1
	}
	n, perr := unix.Poll(pfd, pollMs)
	if perr != nil || n == 0 {
		// Timed out — likely silent drop. Last-chance drain just in case
		// the ICMP arrived during the poll-exit window.
		if origin, ok := drainUDPErrorQueue(fd); ok && origin == soEEOriginICMP {
			return udpClassification{state: "closed", source: "icmp"}
		}
		return udpClassification{state: "filtered", source: "timeout"}
	}

	// POLLERR set → drain the error queue.
	if pfd[0].Revents&unix.POLLERR != 0 {
		if origin, ok := drainUDPErrorQueue(fd); ok && origin == soEEOriginICMP {
			return udpClassification{state: "closed", source: "icmp"}
		}
	}

	// POLLIN set → response arrived. The app-layer probe will have read it
	// (separate socket); we don't need to actually consume from our socket.
	// Classify as "open" — but the dispatcher uses the app-layer probe's
	// product/banner to decide; we return open here as a tiebreaker if
	// the app-layer probe couldn't parse the response.
	if pfd[0].Revents&unix.POLLIN != 0 {
		return udpClassification{state: "open", source: "icmp"}
	}

	return udpClassification{state: "filtered", source: "timeout"}
}

// drainUDPErrorQueue reads one MSG_ERRQUEUE message off fd and returns
// the originating ee_origin (e.g., SO_EE_ORIGIN_ICMP) if present. The
// IP_RECVERR ancillary-data layout matches the TCP traceroute code:
// 16-byte sock_extended_err followed by 16-byte offender sockaddr_in.
func drainUDPErrorQueue(fd int) (uint8, bool) {
	buf := make([]byte, 256)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil || oobn == 0 {
		return 0, false
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, false
	}
	for _, m := range cmsgs {
		if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_RECVERR {
			continue
		}
		if len(m.Data) < sockExtErrSize {
			continue
		}
		// ee_origin is at byte offset 4 of sock_extended_err.
		return m.Data[4], true
	}
	return 0, false
}

