package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// RDP / NLA service probe at TCP/3389. Drives an X.224 Connection
// Request → Negotiation Response handshake to identify RDP and its
// supported protocols (PROTOCOL_RDP / SSL / HYBRID / HYBRID_EX).
//
// Wire format references:
//   MS-RDPBCGR §5.3 / §2.2.1   — Connection Initiation
//   ITU-T X.224                  — Class 0 transport
//
// Connection Request packet (X.224 + RDP nego request):
//
//   TPKT header (4 bytes):
//     1B   Version = 0x03
//     1B   Reserved = 0x00
//     2B   Length (big-endian, includes TPKT itself)
//
//   X.224 COTP Connection Request (variable):
//     1B   Length indicator (rest of X.224 portion)
//     1B   CR-TPDU code = 0xE0
//     2B   DST-REF = 0x0000
//     2B   SRC-REF = 0x0000
//     1B   Class = 0x00
//
//   Optional RDP nego data (8 bytes):
//     1B   Type = 0x01 (RDP_NEG_REQ)
//     1B   Flags = 0x00
//     2B   Length = 0x0008 (little-endian)
//     4B   Requested protocols bitmask (little-endian)
//
// Response RDP_NEG_RSP (type=0x02) carries:
//     1B   Type = 0x02
//     1B   Flags
//     2B   Length = 0x0008
//     4B   Selected protocol
//
// Response RDP_NEG_FAILURE (type=0x03) carries:
//     1B   Type = 0x03
//     1B   Flags
//     2B   Length
//     4B   Failure code (SSL_NOT_ALLOWED_BY_SERVER=2, INCONSISTENT_FLAGS=3, ...)
//
// A successful nego response indicates the server's PREFERRED protocol
// stack. Common values:
//   0 = legacy RDP (no TLS) — major security concern
//   1 = TLS                  — modern but no NLA
//   2 = HYBRID / CredSSP NLA — strongest pre-auth
//   8 = HYBRID_EX            — Win10+ improvements
//
// Full CredSSP NTLM-AV (negotiate / challenge / auth) requires several
// more rounds of SPNEGO + GSS-API + NTLMSSP. We stop at the nego
// response — that already gives us all the protocol-posture signals
// netdoc cares about.

const (
	rdpProtoRDP      = 0x00000000 // legacy MS-RDPBCGR
	rdpProtoSSL      = 0x00000001
	rdpProtoHybrid   = 0x00000002
	rdpProtoRDSTLS   = 0x00000004
	rdpProtoHybridEX = 0x00000008
	rdpProtoRDSAAD   = 0x00000010
)

func probeRDP(addr, _ string, timeout time.Duration) serviceInfo {
	var empty serviceInfo
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return empty
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build X.224 + RDP nego request offering ALL protocols. Server
	// picks its preferred (returns RDP_NEG_RSP) or fails (RDP_NEG_FAILURE).
	negoData := make([]byte, 8)
	negoData[0] = 0x01 // RDP_NEG_REQ
	negoData[1] = 0x00
	binary.LittleEndian.PutUint16(negoData[2:4], 8)
	binary.LittleEndian.PutUint32(negoData[4:8], rdpProtoSSL|rdpProtoHybrid|rdpProtoHybridEX|rdpProtoRDSTLS|rdpProtoRDSAAD)

	x224 := make([]byte, 7)
	x224[0] = byte(6 + len(negoData)) // LI
	x224[1] = 0xe0                     // CR
	binary.BigEndian.PutUint16(x224[2:4], 0) // DST-REF
	binary.BigEndian.PutUint16(x224[4:6], 0) // SRC-REF
	x224[6] = 0x00                            // Class 0

	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	totalLen := uint16(4 + len(x224) + len(negoData))
	binary.BigEndian.PutUint16(tpkt[2:4], totalLen)

	pkt := append(append(tpkt, x224...), negoData...)
	if _, err := conn.Write(pkt); err != nil {
		return empty
	}

	// Read response TPKT header.
	rb := make([]byte, 4)
	if _, err := readFullSMB(conn, rb); err != nil {
		return empty
	}
	if rb[0] != 0x03 {
		return empty
	}
	respLen := int(binary.BigEndian.Uint16(rb[2:4]))
	if respLen < 11 || respLen > 1024 {
		return empty
	}
	rest := make([]byte, respLen-4)
	if _, err := readFullSMB(conn, rest); err != nil {
		return empty
	}

	// rest[0]=LI, rest[1]=CC (0xD0 confirms connection), rest[2:4]=DST-REF,
	// rest[4:6]=SRC-REF, rest[6]=class
	if len(rest) < 7 || rest[1] != 0xd0 {
		return empty
	}
	info := serviceInfo{Product: "RDP", Extra: map[string]string{}}

	// Anything after byte 7 is RDP nego data.
	if len(rest) >= 7+8 {
		negoResp := rest[7:]
		switch negoResp[0] {
		case 0x02: // RDP_NEG_RSP
			selected := binary.LittleEndian.Uint32(negoResp[4:8])
			info.Banner = fmt.Sprintf("RDP nego ok — selected protocol: %s", rdpProtocolName(selected))
			info.Version = rdpProtocolName(selected)
			info.Extra["protocol_selected"] = rdpProtocolName(selected)
			info.Extra["protocol_code"] = fmt.Sprintf("0x%08x", selected)
			info.Extra["nla_required"] = "false"
			if selected&rdpProtoHybrid != 0 || selected&rdpProtoHybridEX != 0 {
				info.Extra["nla_required"] = "true"
			}
		case 0x03: // RDP_NEG_FAILURE
			code := binary.LittleEndian.Uint32(negoResp[4:8])
			info.Banner = fmt.Sprintf("RDP nego refused — code 0x%x (%s)", code, rdpFailureName(code))
			info.Extra["nego_failure_code"] = fmt.Sprintf("0x%08x", code)
			info.Extra["nego_failure_reason"] = rdpFailureName(code)
		default:
			info.Banner = "RDP server responded with unknown nego type 0x" + hex.EncodeToString(negoResp[:1])
		}
	} else {
		// No RDP nego data → legacy RDP only (no TLS).
		info.Banner = "RDP server responded but offered no TLS / NLA — legacy MS-RDPBCGR only"
		info.Version = "Legacy RDP"
		info.Extra["protocol_selected"] = "RDP (legacy, no TLS)"
		info.Extra["nla_required"] = "false"
	}
	return info
}

// rdpProtocolName returns the human-readable name(s) for the selected
// protocol bitmask. Server returns ONE selected protocol (typically),
// but we OR-walk for completeness.
func rdpProtocolName(p uint32) string {
	var names []string
	if p == 0 {
		return "RDP (legacy)"
	}
	if p&rdpProtoSSL != 0 {
		names = append(names, "TLS")
	}
	if p&rdpProtoHybrid != 0 {
		names = append(names, "CredSSP/NLA")
	}
	if p&rdpProtoHybridEX != 0 {
		names = append(names, "CredSSP-EX")
	}
	if p&rdpProtoRDSTLS != 0 {
		names = append(names, "RDSTLS")
	}
	if p&rdpProtoRDSAAD != 0 {
		names = append(names, "RDS-AAD")
	}
	if len(names) == 0 {
		return fmt.Sprintf("unknown 0x%08x", p)
	}
	return strings.Join(names, "+")
}

// rdpFailureName decodes the RDP_NEG_FAILURE code (MS-RDPBCGR §2.2.1.2.2).
func rdpFailureName(code uint32) string {
	switch code {
	case 1:
		return "SSL_REQUIRED_BY_SERVER"
	case 2:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 3:
		return "SSL_CERT_NOT_ON_SERVER"
	case 4:
		return "INCONSISTENT_FLAGS"
	case 5:
		return "HYBRID_REQUIRED_BY_SERVER"
	case 6:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	default:
		return "unknown"
	}
}
