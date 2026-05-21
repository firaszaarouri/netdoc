package main

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Encrypted ClientHello (ECH) detection. RFC 9460 defines the HTTPS resource
// record, which carries SvcParam key 5 (`ech=<base64 ECHConfigList>`) when
// the origin publishes an ECH configuration. Browsers that support ECH
// (Chrome 117+, Firefox 118+) consume this to encrypt the SNI on the wire.
//
// No major CLI tool currently surfaces ECH posture. testssl.sh 3.2 has zero
// mentions of ECH per agent audit. We probe by querying the HTTPS record
// and parsing the ech= parameter; presence → ECH supported, absence →
// not configured. We also parse the bare bytes of the ECH config to
// extract the public-key length + cipher-suite count for the report.
//
// References:
//   RFC 9460 §7.1.5 (HTTPS record + ech=)
//   draft-ietf-tls-esni-17 (ECHConfig wire format)
//   IANA SvcParamKey registry: https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml

// echPosture records what we learned from a HTTPS/SVCB query for ECH.
type echPosture struct {
	Supported       bool   `json:"supported"`
	ConfigCount     int    `json:"config_count,omitempty"`
	Version         uint16 `json:"version,omitempty"`         // 0xfe0d for draft-13
	CipherSuiteCount int   `json:"cipher_suite_count,omitempty"`
	PublicKeyBits   int    `json:"public_key_bits,omitempty"` // length in bytes ×8
	RawLength       int    `json:"raw_length,omitempty"`      // total bytes of ech= value
}

// probeECH queries the HTTPS resource record for the host and parses the
// ech= SvcParam if present. Empty result (Supported=false) is the common
// case in 2026 — ECH is opt-in.
func probeECH(host string, transport *dnsTransport, timeout time.Duration) echPosture {
	var out echPosture
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	rrs, err := queryDNS(host, dns.TypeHTTPS, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return out
	}
	for _, rr := range rrs {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range https.Value {
			ech, ok := kv.(*dns.SVCBECHConfig)
			if !ok {
				continue
			}
			raw := ech.ECH
			if len(raw) == 0 {
				continue
			}
			out.Supported = true
			out.RawLength = len(raw)
			parseECHConfigList(raw, &out)
			return out
		}
	}
	return out
}

// parseECHConfigList extracts the high-level shape of an ECHConfigList from
// its wire bytes. ECHConfigList format (draft-ietf-tls-esni-17):
//
//	struct {
//	    uint16 length;
//	    ECHConfig configs[length];
//	} ECHConfigList;
//
//	struct {
//	    uint16 version;
//	    uint16 length;
//	    select (version) {
//	        case 0xfe0d: ECHConfigContents contents;
//	    }
//	} ECHConfig;
//
//	struct {
//	    HpkeKeyConfig key_config;          // varies; starts with uint8 config_id + uint16 kem_id + opaque public_key<1..2^16-1> + HpkeSymmetricCipherSuite cipher_suites<4..2^16-1>
//	    uint8 maximum_name_length;
//	    opaque public_name<1..255>;
//	    Extension extensions<0..2^16-1>;
//	} ECHConfigContents;
func parseECHConfigList(raw []byte, out *echPosture) {
	if len(raw) < 2 {
		return
	}
	listLen := int(raw[0])<<8 | int(raw[1])
	if 2+listLen > len(raw) {
		return
	}
	body := raw[2 : 2+listLen]
	count := 0
	i := 0
	for i+4 <= len(body) {
		version := uint16(body[i])<<8 | uint16(body[i+1])
		configLen := int(body[i+2])<<8 | int(body[i+3])
		if i+4+configLen > len(body) {
			break
		}
		count++
		if count == 1 {
			out.Version = version
			// Parse ECHConfigContents for the first config — most ECH
			// deployments serve one config at a time.
			contents := body[i+4 : i+4+configLen]
			parseECHConfigContents(contents, out)
		}
		i += 4 + configLen
	}
	out.ConfigCount = count
}

// parseECHConfigContents extracts public-key bit length and cipher-suite count
// from the contents body. Layout (HpkeKeyConfig):
//   config_id(1) + kem_id(2) + public_key<1..2^16-1>(2+N) + cipher_suites<4..2^16-1>(2+M)
// then maximum_name_length(1), public_name(1+N), extensions(2+N).
func parseECHConfigContents(b []byte, out *echPosture) {
	if len(b) < 3 {
		return
	}
	// Skip config_id (1) + kem_id (2)
	off := 3
	if off+2 > len(b) {
		return
	}
	pubLen := int(b[off])<<8 | int(b[off+1])
	off += 2
	if off+pubLen > len(b) {
		return
	}
	out.PublicKeyBits = pubLen * 8
	off += pubLen
	if off+2 > len(b) {
		return
	}
	suitesLen := int(b[off])<<8 | int(b[off+1])
	// Each HpkeSymmetricCipherSuite is 4 bytes (kdf_id(2) + aead_id(2)).
	out.CipherSuiteCount = suitesLen / 4
}

// echHeadline returns "ECH supported" or empty for the hint line. We don't
// shout when ECH is missing because that's the common case for 2026 web —
// only confirmation is interesting.
func echHeadline(p echPosture) string {
	if !p.Supported {
		return ""
	}
	parts := []string{"ECH"}
	if p.Version == 0xfe0d {
		parts = append(parts, "draft-13")
	}
	if p.ConfigCount > 0 {
		parts = append(parts, "×"+itoa(p.ConfigCount))
	}
	return strings.Join(parts, " ")
}
