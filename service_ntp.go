package main

import (
	"net"
	"strings"
	"time"
)

// NTP readvar (mode 6, opcode 2) service probe. NTP's control protocol
// lets administrators query a server's runtime variables — software
// version, system, stratum, precision, refid — via a UDP/123 control
// packet. Most BIND/ntpd/chrony deployments respond to anonymous readvar
// requests with no auth required.
//
// nmap's `ntp-info` NSE script does the same probe. netdoc auto-runs it
// when port 123 is included in --ports (via the service-probe dispatcher).
//
// Wire format (RFC 5905 §7.5 + §8 NTP control messages):
//   0      1      2      3
//   LI VN MODE  OP/EVENT  Sequence  Association ID
//   Status              Offset             Count
//   Data (variable)              Authenticator (optional)
//
// Mode 6 is the control message subtype. Opcode 2 = read variables.
// We send a minimal "readvar" with empty data + no association ID;
// the response carries the variables as ASCII "name=value, name=value..."
//
// Reference: https://datatracker.ietf.org/doc/html/rfc5905

// ntpResult is the parsed NTP readvar response.
type ntpResult struct {
	Probed     bool   `json:"probed"`
	Version    string `json:"version,omitempty"`    // "ntpd 4.2.8p15"
	System     string `json:"system,omitempty"`     // "Linux/5.15.0-..."
	Stratum    string `json:"stratum,omitempty"`
	Precision  string `json:"precision,omitempty"`
	RefID      string `json:"refid,omitempty"`
	Processor  string `json:"processor,omitempty"`
	Banner     string `json:"banner,omitempty"`     // one-line summary
}

func probeNTP(addr, _ string, timeout time.Duration) serviceInfo {
	// Empty serviceInfo means "no response, no evidence of NTP". We only
	// populate Product once we've confirmed an NTP-format reply.
	var empty serviceInfo

	// Override default TCP dispatcher with UDP for NTP. NTP control runs
	// on UDP/123.
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return empty
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build readvar request: 12-byte NTP control header.
	//   byte 0: LI=0, VN=2, MODE=6     = 0x16
	//   byte 1: R=0, E=0, M=0, OP=2    = 0x02
	//   bytes 2-3: sequence            = 0x0001
	//   bytes 4-5: status              = 0x0000
	//   bytes 6-7: association ID      = 0x0000
	//   bytes 8-9: offset              = 0x0000
	//   bytes 10-11: count             = 0x0000
	req := []byte{
		0x16, 0x02,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	if _, err := conn.Write(req); err != nil {
		return empty
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return empty
	}
	// Bytes 0,1 should mirror our values with R bit set in byte 1.
	if buf[0] != 0x16 || (buf[1]&0x1f) != 0x02 {
		// Not an NTP control response — could be ICMP-derived garbage
		// or a non-NTP service squatting on UDP/123. Don't claim NTP.
		return empty
	}
	// At this point we've confirmed an NTP-format control response.
	info := serviceInfo{Product: "NTP"}
	count := int(buf[10])<<8 | int(buf[11])
	if 12+count > n {
		count = n - 12
	}
	body := string(buf[12 : 12+count])
	info.Banner = strings.TrimSpace(body)

	// Parse comma-separated "name=value" pairs.
	out := serviceInfo{Product: "NTP", Extra: map[string]string{}}
	for _, pair := range strings.Split(body, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(strings.Trim(v, "\""))
		switch k {
		case "version":
			out.Version = v
			out.Extra["version"] = v
		case "system":
			out.Extra["system"] = v
		case "processor":
			out.Extra["processor"] = v
		case "stratum":
			out.Extra["stratum"] = v
		case "precision":
			out.Extra["precision"] = v
		case "refid":
			out.Extra["refid"] = v
		case "leap":
			out.Extra["leap"] = v
		case "rootdelay":
			out.Extra["rootdelay"] = v
		case "rootdisp":
			out.Extra["rootdisp"] = v
		case "tc":
			out.Extra["tc"] = v
		case "mintc":
			out.Extra["mintc"] = v
		}
	}
	out.Banner = strings.TrimSpace(body)
	return out
}
