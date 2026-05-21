package main

import (
	"encoding/binary"
	"io"
	"time"
)

// LDAP rootDSE service probe — hand-rolled BER-encoded LDAPv3 anonymous
// bind + search of the rootDSE. RFC 4513 §5.1 specifies that LDAP servers
// MUST allow anonymous bind by default unless administratively disabled,
// and RFC 4511 §4.1.1 makes the rootDSE (empty base DN) readable to all.
//
// We extract: vendorName, vendorVersion, supportedLDAPVersion,
// supportedSASLMechanisms, supportedControl, dnsHostName, namingContexts.
//
// AD doesn't fill vendorName but DOES expose namingContexts (which
// includes the domain DN like DC=example,DC=com), defaultNamingContext,
// and dnsHostName. Modern OpenLDAP / 389-DS expose vendorVersion as a
// version string. Either is fingerprint enough.
//
// References:
//   RFC 4511 (LDAPv3 protocol)
//   RFC 4513 (Authentication)
//   RFC 3045 (rootDSE attributes)

func probeLDAP(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "LDAP"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	// Step 1: anonymous bind (LDAPv3, mech=simple, empty creds).
	// BindRequest packet (BER):
	//   30 [seq-len]
	//     02 01 01            -- message ID 1
	//     60 [bind-len]       -- BindRequest application 0
	//       02 01 03          -- version 3
	//       04 00             -- name (empty)
	//       80 00             -- authentication choice 0 (simple), value empty
	bindReq := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}
	if _, err := conn.Write(bindReq); err != nil {
		return info
	}
	// Read BindResponse — we ignore the result code; even on failure,
	// some LDAP servers still answer rootDSE queries.
	if !readLDAPResponse(conn, timeout) {
		// Continue anyway — some servers don't reply to bind but answer
		// rootDSE.
	}

	// Step 2: SearchRequest for rootDSE.
	// SearchRequest [APPLICATION 3]:
	//   baseObject     ""
	//   scope          baseObject (0)
	//   derefAliases   neverDerefAliases (0)
	//   sizeLimit      0
	//   timeLimit      30
	//   typesOnly      FALSE
	//   filter         (objectClass=*) — present filter, attr=objectClass
	//   attributes     [vendorName, vendorVersion, supportedLDAPVersion,
	//                   supportedSASLMechanisms, namingContexts,
	//                   defaultNamingContext, dnsHostName]
	searchReq := buildLDAPSearchRequest(2)
	if _, err := conn.Write(searchReq); err != nil {
		return info
	}

	// Read SearchResultEntry + SearchResultDone.
	info.Extra = map[string]string{}
	for {
		ok, payload, msgType := readLDAPMessage(conn, timeout)
		if !ok {
			break
		}
		if msgType == 0x64 { // SearchResultEntry [APPLICATION 4]
			parseRootDSEAttributes(payload, info.Extra)
		}
		if msgType == 0x65 { // SearchResultDone [APPLICATION 5]
			break
		}
	}

	// Set product/version from extracted attributes.
	if v := info.Extra["vendorName"]; v != "" {
		info.Product = v
	}
	if v := info.Extra["vendorVersion"]; v != "" {
		info.Version = v
	} else if v := info.Extra["dnsHostName"]; v != "" {
		info.Banner = "AD host: " + v
	}
	return info
}

func buildLDAPSearchRequest(msgID byte) []byte {
	// Hand-build a SearchRequest. Format gets verbose in BER, so we
	// construct the inner parts then prepend lengths.
	attributes := []string{
		"vendorName", "vendorVersion", "supportedLDAPVersion",
		"supportedSASLMechanisms", "namingContexts",
		"defaultNamingContext", "dnsHostName", "serverName",
		"isGlobalCatalogReady",
	}
	attrSeq := []byte{}
	for _, a := range attributes {
		attrSeq = append(attrSeq, 0x04, byte(len(a)))
		attrSeq = append(attrSeq, []byte(a)...)
	}
	attrSeq = append([]byte{0x30, byte(len(attrSeq))}, attrSeq...)

	// filter: (objectClass=*) - present filter [7] with value "objectClass"
	filter := []byte{0x87, 0x0b}
	filter = append(filter, []byte("objectClass")...)

	body := []byte{
		0x04, 0x00, // baseObject empty
		0x0a, 0x01, 0x00, // scope baseObject(0)
		0x0a, 0x01, 0x00, // derefAliases neverDerefAliases(0)
		0x02, 0x01, 0x00, // sizeLimit 0
		0x02, 0x01, 0x1e, // timeLimit 30
		0x01, 0x01, 0x00, // typesOnly FALSE
	}
	body = append(body, filter...)
	body = append(body, attrSeq...)
	search := append([]byte{0x63, byte(len(body))}, body...) // [APPLICATION 3]

	msg := []byte{0x02, 0x01, msgID}
	msg = append(msg, search...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func readLDAPResponse(c io.Reader, timeout time.Duration) bool {
	_, _, _ = readLDAPMessage(c, timeout)
	return true
}

// readLDAPMessage reads one BER-encoded LDAPMessage. Returns the inner
// (msgID-stripped) protocol-op body and its message-type tag.
func readLDAPMessage(c io.Reader, timeout time.Duration) (bool, []byte, byte) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return false, nil, 0
	}
	if hdr[0] != 0x30 { // SEQUENCE
		return false, nil, 0
	}
	// Length: short form OR long form (top bit set = N length-bytes follow).
	totalLen := int(hdr[1])
	if totalLen&0x80 != 0 {
		nlen := totalLen & 0x7f
		if nlen == 0 || nlen > 4 {
			return false, nil, 0
		}
		lenBytes := make([]byte, nlen)
		if _, err := io.ReadFull(c, lenBytes); err != nil {
			return false, nil, 0
		}
		totalLen = 0
		for _, b := range lenBytes {
			totalLen = (totalLen << 8) | int(b)
		}
	}
	if totalLen <= 0 || totalLen > 64*1024 {
		return false, nil, 0
	}
	body := make([]byte, totalLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return false, nil, 0
	}
	// Skip messageID (INTEGER).
	if len(body) < 5 || body[0] != 0x02 {
		return false, nil, 0
	}
	idLen := int(body[1])
	off := 2 + idLen
	if off >= len(body) {
		return false, nil, 0
	}
	return true, body[off:], body[off]
}

// parseRootDSEAttributes walks a SearchResultEntry body, extracting
// attribute names + values into the Extra map.
//
// SearchResultEntry [APPLICATION 4] ::= SEQUENCE {
//     objectName     LDAPDN,
//     attributes     PartialAttributeList }
//   PartialAttributeList ::= SEQUENCE OF PartialAttribute
//   PartialAttribute ::= SEQUENCE {
//     type    AttributeDescription,  (OCTET STRING)
//     vals    SET OF AttributeValue }
func parseRootDSEAttributes(body []byte, extra map[string]string) {
	// Skip the leading [APPLICATION 4] tag + len.
	if len(body) < 2 || (body[0]&0x1f) != 0x04 {
		return
	}
	innerLen := int(body[1])
	if innerLen&0x80 != 0 {
		// long form
		nlen := innerLen & 0x7f
		if nlen == 0 || 2+nlen >= len(body) {
			return
		}
		innerLen = 0
		for i := 0; i < nlen; i++ {
			innerLen = (innerLen << 8) | int(body[2+i])
		}
		body = body[2+nlen:]
	} else {
		body = body[2:]
	}
	// Skip objectName (OCTET STRING).
	if len(body) < 2 || body[0] != 0x04 {
		return
	}
	nameLen := int(body[1])
	body = body[2+nameLen:]
	// Now PartialAttributeList — a SEQUENCE OF.
	if len(body) < 2 || body[0] != 0x30 {
		return
	}
	listLen := int(body[1])
	if listLen&0x80 != 0 {
		nlen := listLen & 0x7f
		if nlen == 0 || 2+nlen >= len(body) {
			return
		}
		listLen = 0
		for i := 0; i < nlen; i++ {
			listLen = (listLen << 8) | int(body[2+i])
		}
		body = body[2+nlen:]
	} else {
		body = body[2:]
	}
	end := listLen
	if end > len(body) {
		end = len(body)
	}
	body = body[:end]
	// Walk attributes.
	for len(body) > 0 {
		if body[0] != 0x30 {
			return
		}
		attrLen, attrHdrLen := berLen(body[1:])
		if attrHdrLen == 0 || 1+attrHdrLen+attrLen > len(body) {
			return
		}
		attrBody := body[1+attrHdrLen : 1+attrHdrLen+attrLen]
		body = body[1+attrHdrLen+attrLen:]

		// First element: OCTET STRING with attribute name.
		if len(attrBody) < 2 || attrBody[0] != 0x04 {
			continue
		}
		nameLen := int(attrBody[1])
		if 2+nameLen > len(attrBody) {
			continue
		}
		name := string(attrBody[2 : 2+nameLen])
		rest := attrBody[2+nameLen:]
		// rest: SET OF AttributeValue
		if len(rest) < 2 || rest[0] != 0x31 {
			continue
		}
		setLen, setHdrLen := berLen(rest[1:])
		if setHdrLen == 0 || 1+setHdrLen+setLen > len(rest) {
			continue
		}
		setBody := rest[1+setHdrLen : 1+setHdrLen+setLen]
		// First value only — for fingerprint purposes.
		if len(setBody) < 2 || setBody[0] != 0x04 {
			continue
		}
		vlen := int(setBody[1])
		if 2+vlen > len(setBody) {
			continue
		}
		val := string(setBody[2 : 2+vlen])
		extra[name] = val
	}
	_ = binary.BigEndian // keep import live
}

// berLen reads a BER length from `b`. Returns (value, header-bytes-consumed).
func berLen(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1
	}
	nlen := int(b[0] & 0x7f)
	if nlen == 0 || nlen > 4 || 1+nlen > len(b) {
		return 0, 0
	}
	v := 0
	for i := 0; i < nlen; i++ {
		v = (v << 8) | int(b[1+i])
	}
	return v, 1 + nlen
}
