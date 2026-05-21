//go:build !linux

package main

import (
	"net"
	"time"
)

// Non-Linux UDP classifier — no IP_RECVERR equivalent unprivileged. We
// degrade to "open|filtered" when there's no response, with no way to
// confirm closed-vs-filtered without raw-socket admin (which would break
// the unprivileged-binary brand).
//
// The app-layer probe (e.g., service_ntp.go) still runs on these
// platforms via the cross-platform UDP scan dispatcher — only the
// closed-vs-filtered determination is unavailable.

func classifyUDPPort(target net.IP, port int, payload []byte, timeout time.Duration) udpClassification {
	// We don't bother sending a UDP probe here because the app-layer probe
	// in udpServicePortMap already does. Return "open|filtered" so the
	// dispatcher knows to label the port that way when the probe gets no
	// response. Linux gets the closed-vs-filtered distinction.
	return udpClassification{state: "open|filtered", source: "platform"}
}
