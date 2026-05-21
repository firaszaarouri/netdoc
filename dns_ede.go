package main

// Extended DNS Errors (RFC 8914) — when a resolver returns a non-success
// rcode, the EDE option in OPT-record EDNS0 carries an INFO-CODE explaining
// *why*. Surfacing these turns "SERVFAIL" from a black box into "stale data
// (info-code 3)" or "DNSSEC bogus (info-code 6)" etc.
//
// Source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes
//
// We embed the IANA registry as of 2026-05-20. Refresh annually as IANA
// adds codes.

// edeCodes maps RFC 8914 INFO-CODEs to human-readable purposes. Some entries
// add a one-line "what to do" hint after the colon.
var edeCodes = map[uint16]string{
	0:  "Other Error",
	1:  "Unsupported DNSKEY Algorithm",
	2:  "Unsupported DS Digest Type",
	3:  "Stale Answer (out-of-date data from cache)",
	4:  "Forged Answer (resolver believes record is malicious)",
	5:  "DNSSEC Indeterminate (chain didn't validate but wasn't bogus)",
	6:  "DNSSEC Bogus (chain failed validation)",
	7:  "Signature Expired",
	8:  "Signature Not Yet Valid",
	9:  "DNSKEY Missing",
	10: "RRSIG Missing",
	11: "No Zone Key Bit Set",
	12: "NSEC Missing",
	13: "Cached Error (negative result was cached)",
	14: "Not Ready (recursive resolver still working)",
	15: "Blocked (administratively blocked)",
	16: "Censored (blocked by external authority)",
	17: "Filtered (blocked at request of client)",
	18: "Prohibited (resolver doesn't serve this query)",
	19: "Stale NXDOMAIN Answer (negative result from stale cache)",
	20: "Not Authoritative (resolver isn't authoritative for this zone)",
	21: "Not Supported (resolver doesn't implement this query type)",
	22: "No Reachable Authority (couldn't reach any auth NS)",
	23: "Network Error",
	24: "Invalid Data (received malformed DNS data upstream)",
	25: "Signature Expired Before Valid",
	26: "Too Early (early data not allowed)",
	27: "Unsupported NSEC3 Iterations Value",
	28: "Unable To Conform To Policy",
	29: "Synthesized (record was synthesized, not retrieved)",
}

// describeEDE returns a human-readable description of an EDE info-code, or
// a fallback "EDE code N" string for unknown codes.
func describeEDE(infoCode uint16, extraText string) string {
	desc, ok := edeCodes[infoCode]
	if !ok {
		desc = "EDE code " + uint16str(infoCode)
	}
	if extraText != "" {
		return desc + " — " + extraText
	}
	return desc
}

func uint16str(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + byte(v%10)
		v /= 10
	}
	return string(buf[i:])
}
