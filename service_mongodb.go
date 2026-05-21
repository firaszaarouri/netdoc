package main

import (
	"encoding/binary"
	"io"
	"time"
)

// MongoDB version probe via OP_MSG hello command. Modern MongoDB (5.1+)
// removed legacy OP_QUERY, so we speak OP_MSG. The hello command is
// unauthenticated — any MongoDB server answers it, returning a BSON document
// containing `maxWireVersion` which we map to the MongoDB major version.
//
// Wire reference: https://github.com/mongodb/specifications/blob/master/source/message/OP_MSG.md
// hello reference: https://www.mongodb.com/docs/manual/reference/command/hello/
// wire-version table: https://www.mongodb.com/docs/manual/reference/wire-protocol-versions/

var mongoWireToVersion = map[int32]string{
	25: "8.0",
	21: "7.0",
	17: "6.0",
	13: "5.0",
	9:  "4.4",
	8:  "4.2",
	7:  "4.0",
	6:  "3.6",
	5:  "3.4",
}

func probeMongoDB(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "MongoDB"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return serviceInfo{}
	}
	defer conn.Close()

	msg := buildMongoHelloMessage()
	if _, err := conn.Write(msg); err != nil {
		return info
	}

	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return info
	}
	totalLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	opCode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
	if opCode != 2013 {
		return info
	}
	bodyLen := int(totalLen) - 16
	if bodyLen <= 0 || bodyLen > 16*1024*1024 {
		return info
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return info
	}
	if len(body) < 5 {
		return info
	}
	kind := body[4]
	if kind != 0 {
		return info
	}
	doc := body[5:]
	fields := scanBSONFields(doc)
	if mwv, ok := fields["maxWireVersion"]; ok {
		if wire, ok2 := mwv.(int32); ok2 {
			if v, mapped := mongoWireToVersion[wire]; mapped {
				info.Version = v
			} else if wire > 25 {
				info.Version = "8.x+ (wire " + i32str(wire) + ")"
			} else {
				info.Version = "wire " + i32str(wire)
			}
			info.Extra = map[string]string{"max_wire_version": i32str(wire)}
		}
	}
	if minWire, ok := fields["minWireVersion"]; ok {
		if w, ok2 := minWire.(int32); ok2 {
			if info.Extra == nil {
				info.Extra = map[string]string{}
			}
			info.Extra["min_wire_version"] = i32str(w)
		}
	}
	if v, ok := fields["isWritablePrimary"]; ok {
		if b, ok2 := v.(bool); ok2 {
			if info.Extra == nil {
				info.Extra = map[string]string{}
			}
			info.Extra["primary"] = boolStr(b)
		}
	}
	if v, ok := fields["readOnly"]; ok {
		if b, ok2 := v.(bool); ok2 {
			if info.Extra == nil {
				info.Extra = map[string]string{}
			}
			info.Extra["read_only"] = boolStr(b)
		}
	}
	if v, ok := fields["msg"]; ok {
		if s, ok2 := v.(string); ok2 {
			if info.Extra == nil {
				info.Extra = map[string]string{}
			}
			info.Extra["msg"] = s
		}
	}
	info.Banner = "OP_MSG hello — accepted"
	return info
}

// buildMongoHelloMessage assembles an OP_MSG hello command.
func buildMongoHelloMessage() []byte {
	bson := buildHelloBSON()
	body := make([]byte, 0, 5+len(bson))
	body = append(body, 0, 0, 0, 0) // flagBits = 0
	body = append(body, 0)          // kind = 0 (body)
	body = append(body, bson...)

	totalLen := uint32(16 + len(body))
	out := make([]byte, 0, 16+len(body))
	out = append(out,
		byte(totalLen), byte(totalLen>>8), byte(totalLen>>16), byte(totalLen>>24),
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xDD, 0x07, 0x00, 0x00, // opCode = 2013 (OP_MSG)
	)
	out = append(out, body...)
	return out
}

// buildHelloBSON returns the BSON encoding of {hello: 1, "$db": "admin"}.
func buildHelloBSON() []byte {
	doc := make([]byte, 0, 31)
	doc = append(doc, 0, 0, 0, 0) // placeholder for length
	doc = append(doc, 0x10)
	doc = append(doc, []byte("hello\x00")...)
	doc = append(doc, 0x01, 0x00, 0x00, 0x00)
	doc = append(doc, 0x02)
	doc = append(doc, []byte("$db\x00")...)
	doc = append(doc, 0x06, 0x00, 0x00, 0x00)
	doc = append(doc, []byte("admin\x00")...)
	doc = append(doc, 0x00)
	totalLen := uint32(len(doc))
	doc[0] = byte(totalLen)
	doc[1] = byte(totalLen >> 8)
	doc[2] = byte(totalLen >> 16)
	doc[3] = byte(totalLen >> 24)
	return doc
}

// scanBSONFields walks a BSON document and returns a map of named scalar
// fields. Handles only types we need for hello: 0x10 int32, 0x02 string,
// 0x08 bool, plus skip-over for the common types we'd encounter alongside.
func scanBSONFields(doc []byte) map[string]any {
	out := map[string]any{}
	if len(doc) < 5 {
		return out
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen > len(doc) {
		docLen = len(doc)
	}
	i := 4
	for i < docLen-1 {
		tag := doc[i]
		if tag == 0 {
			break
		}
		i++
		nameEnd := i
		for nameEnd < docLen && doc[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= docLen {
			return out
		}
		name := string(doc[i:nameEnd])
		i = nameEnd + 1
		switch tag {
		case 0x10: // int32
			if i+4 > docLen {
				return out
			}
			out[name] = int32(binary.LittleEndian.Uint32(doc[i : i+4]))
			i += 4
		case 0x12: // int64
			if i+8 > docLen {
				return out
			}
			i += 8
		case 0x02: // UTF-8 string
			if i+4 > docLen {
				return out
			}
			slen := int(binary.LittleEndian.Uint32(doc[i : i+4]))
			i += 4
			if i+slen > docLen || slen < 1 {
				return out
			}
			out[name] = string(doc[i : i+slen-1])
			i += slen
		case 0x08: // bool
			if i+1 > docLen {
				return out
			}
			out[name] = doc[i] != 0
			i++
		case 0x01: // double
			if i+8 > docLen {
				return out
			}
			i += 8
		case 0x09: // datetime
			if i+8 > docLen {
				return out
			}
			i += 8
		case 0x07: // ObjectId
			if i+12 > docLen {
				return out
			}
			i += 12
		case 0x03, 0x04: // embedded document/array
			if i+4 > docLen {
				return out
			}
			sublen := int(binary.LittleEndian.Uint32(doc[i : i+4]))
			i += sublen
		case 0x0A: // null
			// no payload
		default:
			return out
		}
	}
	return out
}

func i32str(v int32) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [12]byte
	idx := len(buf)
	for v > 0 {
		idx--
		buf[idx] = '0' + byte(v%10)
		v /= 10
	}
	if neg {
		idx--
		buf[idx] = '-'
	}
	return string(buf[idx:])
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
