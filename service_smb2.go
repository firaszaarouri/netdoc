package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// SMB2 NEGOTIATE probe. Microsoft-DS port 445 (and legacy NetBIOS 139).
//
// Wire format (MS-SMB2 §2.2.3):
//
//   NetBIOS header (4 bytes):
//     1B   message type (0x00 for session message)
//     3B   length (big-endian)
//
//   SMB2 header (64 bytes):
//     4B   ProtocolId = "\xfeSMB"
//     2B   StructureSize = 64
//     2B   CreditCharge
//     4B   Status (request: 0)
//     2B   Command (0x0000 = NEGOTIATE)
//     2B   Credits (request: 1)
//     4B   Flags
//     4B   NextCommand (0 for single op)
//     8B   MessageId
//     4B   Reserved/AsyncId
//     4B   TreeId / TreeID
//     8B   SessionId
//     16B  Signature
//
//   NEGOTIATE Request body (≥36 bytes + dialect list):
//     2B   StructureSize = 36
//     2B   DialectCount
//     2B   SecurityMode (0x01 SIGNING_ENABLED)
//     2B   Reserved
//     4B   Capabilities
//     16B  ClientGuid
//     8B   ClientStartTime (or NegotiateContextOffset/Count for SMB 3.1.1)
//     N×2B Dialects[] — 0x0202 (SMB 2.0.2), 0x0210 (2.1), 0x0300 (3.0),
//                       0x0302 (3.0.2), 0x0311 (3.1.1)
//
// Response NEGOTIATE body (≥65 bytes):
//     2B   StructureSize = 65
//     2B   SecurityMode
//     2B   DialectRevision  ← what the server picked
//     2B   NegotiateContextCount (SMB 3.1.1)
//     16B  ServerGuid       ← MS-SMB2 §2.2.4
//     4B   Capabilities
//     4B   MaxTransactSize
//     4B   MaxReadSize
//     4B   MaxWriteSize
//     8B   SystemTime       (FILETIME, 100ns ticks since 1601-01-01)
//     8B   ServerStartTime  (FILETIME)
//     2B   SecurityBufferOffset
//     2B   SecurityBufferLength
//     ...
//
// The response gives us: SMB dialect range, signing posture, server GUID,
// approximate system time (uptime hint via ServerStartTime), and from
// the dialect a hint at OS family / Windows version.

const (
	smb2DialectV202 = 0x0202
	smb2DialectV210 = 0x0210
	smb2DialectV300 = 0x0300
	smb2DialectV302 = 0x0302
	smb2DialectV311 = 0x0311
	smb2DialectWild = 0x02ff // sent in SMB1 NEGOTIATE for "any SMB2"
)

func probeSMB2(addr, _ string, timeout time.Duration) serviceInfo {
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

	// Build SMB2 NEGOTIATE offering all five dialects.
	dialects := []uint16{smb2DialectV202, smb2DialectV210, smb2DialectV300, smb2DialectV302, smb2DialectV311}

	body := make([]byte, 0, 36+2*len(dialects))
	body = binary.LittleEndian.AppendUint16(body, 36)                 // StructureSize
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects))) // DialectCount
	body = binary.LittleEndian.AppendUint16(body, 0x0001)              // SecurityMode = SIGNING_ENABLED
	body = binary.LittleEndian.AppendUint16(body, 0)                   // Reserved
	body = binary.LittleEndian.AppendUint32(body, 0x0000007f)          // Capabilities (all SMB3 flags)
	// ClientGuid (16 zero bytes — generic probe)
	body = append(body, make([]byte, 16)...)
	// ClientStartTime / NegContext fields — zero
	body = append(body, make([]byte, 8)...)
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}

	// SMB2 header (64 bytes).
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)        // StructureSize
	binary.LittleEndian.PutUint16(hdr[6:8], 0)         // CreditCharge
	// Status=0, Command=0 NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[12:14], 0)       // Command
	binary.LittleEndian.PutUint16(hdr[14:16], 1)       // Credits
	// MessageId=0, all session fields zero

	smbPacket := append(hdr, body...)

	// NetBIOS framing (4 bytes header).
	netbios := make([]byte, 4)
	netbios[0] = 0x00 // session message
	netbios[1] = 0x00
	binary.BigEndian.PutUint16(netbios[2:4], uint16(len(smbPacket)))

	if _, err := conn.Write(append(netbios, smbPacket...)); err != nil {
		return empty
	}

	// Read NetBIOS header.
	rb := make([]byte, 4)
	if _, err := readFullSMB(conn, rb); err != nil {
		return empty
	}
	respLen := int(binary.BigEndian.Uint16(rb[2:4]))
	if respLen < 64+65 || respLen > 64*1024 {
		return empty
	}
	resp := make([]byte, respLen)
	if _, err := readFullSMB(conn, resp); err != nil {
		return empty
	}

	// Validate SMB2 magic.
	if string(resp[0:4]) != "\xfeSMB" {
		return empty
	}
	respBody := resp[64:]
	if len(respBody) < 65 {
		return empty
	}
	if binary.LittleEndian.Uint16(respBody[0:2]) != 65 {
		return empty
	}
	dialect := binary.LittleEndian.Uint16(respBody[4:6])
	if dialect == 0 || dialect == 0xffff {
		return empty
	}
	securityMode := binary.LittleEndian.Uint16(respBody[2:4])
	serverGuid := respBody[8:24]
	maxTransact := binary.LittleEndian.Uint32(respBody[28:32])
	maxRead := binary.LittleEndian.Uint32(respBody[32:36])
	maxWrite := binary.LittleEndian.Uint32(respBody[36:40])
	systemTimeFT := binary.LittleEndian.Uint64(respBody[40:48])
	serverStartFT := binary.LittleEndian.Uint64(respBody[48:56])

	info := serviceInfo{
		Product: "SMB2",
		Extra:   map[string]string{},
	}
	info.Version = smb2DialectName(dialect)
	info.Banner = fmt.Sprintf("SMB %s · signing %s · serverGUID %s",
		smb2DialectName(dialect),
		smb2SigningPosture(securityMode),
		formatGUID(serverGuid))
	info.Extra["dialect"] = fmt.Sprintf("0x%04x", dialect)
	info.Extra["dialect_name"] = smb2DialectName(dialect)
	info.Extra["signing"] = smb2SigningPosture(securityMode)
	info.Extra["server_guid"] = formatGUID(serverGuid)
	info.Extra["max_transact_size"] = itoa(int(maxTransact))
	info.Extra["max_read_size"] = itoa(int(maxRead))
	info.Extra["max_write_size"] = itoa(int(maxWrite))
	if systemTimeFT > 0 {
		t := filetimeToTime(systemTimeFT)
		info.Extra["system_time"] = t.UTC().Format(time.RFC3339)
	}
	if serverStartFT > 0 {
		t := filetimeToTime(serverStartFT)
		info.Extra["server_start"] = t.UTC().Format(time.RFC3339)
		uptime := time.Since(t)
		if uptime > 0 && uptime < 365*24*time.Hour*10 {
			info.Extra["uptime_approx"] = uptime.Truncate(time.Minute).String()
		}
	}
	return info
}

// smb2DialectName maps a dialect code to a human-friendly string.
// Used both as the Version field and in the Extra map.
func smb2DialectName(d uint16) string {
	switch d {
	case smb2DialectV202:
		return "2.0.2 (Vista / 2008)"
	case smb2DialectV210:
		return "2.1 (Win7 / 2008 R2)"
	case smb2DialectV300:
		return "3.0 (Win8 / 2012)"
	case smb2DialectV302:
		return "3.0.2 (8.1 / 2012 R2)"
	case smb2DialectV311:
		return "3.1.1 (Win10 / 2016+)"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}

// smb2SigningPosture interprets the SecurityMode flags. 0x01 = signing
// enabled, 0x02 = signing required.
func smb2SigningPosture(mode uint16) string {
	switch {
	case mode&0x02 != 0:
		return "required"
	case mode&0x01 != 0:
		return "enabled"
	default:
		return "disabled"
	}
}

// formatGUID turns 16 raw bytes into the canonical Microsoft GUID format
// (8-4-4-4-12) with little-endian byte ordering on the first three groups
// per RFC 4122 §3 (the Microsoft variant used by SMB).
func formatGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// filetimeToTime converts a Windows FILETIME (100ns ticks since
// 1601-01-01 UTC) to time.Time. SMB2 uses FILETIME in NEGOTIATE
// SystemTime and ServerStartTime fields.
func filetimeToTime(ft uint64) time.Time {
	const ftEpoch = 116444736000000000   // ticks from 1601-01-01 to 1970-01-01
	const ticksPerSecond = 10_000_000    // 100ns ticks per second
	if ft < ftEpoch {
		return time.Time{}
	}
	unixTicks := ft - ftEpoch
	sec := int64(unixTicks / ticksPerSecond)
	nsec := int64(unixTicks%ticksPerSecond) * 100
	return time.Unix(sec, nsec)
}

// readFullSMB reads len(buf) bytes from conn with the existing deadline.
// Tiny helper so we don't pull in io.ReadFull just for this.
func readFullSMB(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
