package main

import (
	"encoding/binary"
	"io"
	"time"
)

// PostgreSQL version probe. PG doesn't volunteer a banner on connect, so we
// send a minimal StartupMessage with a bogus user — the server replies with
// an ErrorResponse whose 'V' Severity-V field (added in PG 9.3) tells us
// "at least 9.3". The full error message + code give us further fingerprinting.
//
// Wire format: https://www.postgresql.org/docs/current/protocol-message-formats.html

func probePostgreSQL(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "PostgreSQL"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return serviceInfo{}
	}
	defer conn.Close()

	payload := []byte{0x00, 0x03, 0x00, 0x00} // protocol version 3.0 (196608)
	payload = append(payload, []byte("user\x00netdoc_probe\x00database\x00postgres\x00application_name\x00netdoc\x00\x00")...)
	length := uint32(len(payload) + 4)
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, length)
	msg = append(msg, payload...)

	if _, err := conn.Write(msg); err != nil {
		return info
	}

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return info
	}
	if hdr[0] != 'E' {
		info.Banner = "PG response type: " + string(hdr[0])
		return info
	}
	bodyLen := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if bodyLen <= 0 || bodyLen > 16*1024 {
		return info
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return info
	}

	info.Extra = map[string]string{}
	i := 0
	for i < len(body) {
		fieldType := body[i]
		if fieldType == 0 {
			break
		}
		i++
		end := i
		for end < len(body) && body[end] != 0 {
			end++
		}
		value := string(body[i:end])
		switch fieldType {
		case 'S':
			info.Extra["severity"] = value
		case 'V':
			info.Extra["severity_v"] = value
		case 'C':
			info.Extra["code"] = value
		case 'M':
			info.Banner = value
		case 'R':
			info.Extra["routine"] = value
		case 'F':
			info.Extra["file"] = value
		case 'L':
			info.Extra["line"] = value
		}
		i = end + 1
	}
	if _, ok := info.Extra["severity_v"]; ok {
		info.Version = ">=9.3"
	} else {
		info.Version = "<9.3 (no Severity-V field)"
	}
	return info
}
