package main

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// BIMI (Brand Indicators for Message Identification) record probe. BIMI is
// the email-brand-authenticity layer: when DMARC enforcement is "quarantine"
// or "reject" AND the domain publishes a BIMI record at
// `default._bimi.<domain>`, supporting MUAs (Gmail, Apple Mail, Yahoo) can
// display the brand's logo next to the sender. MXToolbox surfaces BIMI;
// most CLI tools do not.
//
// Wire format: TXT record at the BIMI selector — typically `default._bimi`.
// The record's value is a semicolon-separated tag list:
//
//   v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem
//
// l= is the SVG logo URI (RFC requires SVG Tiny PS profile).
// a= is the Verified Mark Certificate URI (Entrust/DigiCert issue these).
//
// Reference: https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/

// bimiRecord is what we parsed from a domain's BIMI TXT.
type bimiRecord struct {
	Found  bool   `json:"found"`
	Raw    string `json:"raw,omitempty"`
	Logo   string `json:"logo,omitempty"`   // l=
	VMC    string `json:"vmc,omitempty"`    // a= (Verified Mark Certificate)
	Errors []string `json:"errors,omitempty"`
}

// probeBIMI queries default._bimi.<domain> TXT and parses it.
func probeBIMI(domain string, transport *dnsTransport, timeout time.Duration) bimiRecord {
	var out bimiRecord
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	name := "default._bimi." + strings.TrimSuffix(domain, ".")
	rrs, err := queryDNS(name, dns.TypeTXT, transport, timeout)
	if err != nil || len(rrs) == 0 {
		return out
	}
	var combined string
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			combined = strings.Join(txt.Txt, "")
			break
		}
	}
	if combined == "" {
		return out
	}
	out.Found = true
	out.Raw = combined
	// Tag parser — same shape as SPF / DMARC: semicolon-delimited k=v pairs.
	for _, part := range strings.Split(combined, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "v":
			if v != "BIMI1" {
				out.Errors = append(out.Errors, "unknown version: "+v)
			}
		case "l":
			out.Logo = v
		case "a":
			out.VMC = v
		}
	}
	if out.Logo == "" {
		out.Errors = append(out.Errors, "no l= (logo URI)")
	}
	if strings.HasPrefix(out.Logo, "http://") {
		out.Errors = append(out.Errors, "l= must be https://")
	}
	return out
}

// bimiHeadline returns a hint-line summary like "BIMI: logo + VMC" or
// "BIMI: logo (no VMC)". Empty when no record.
func bimiHeadline(b bimiRecord) string {
	if !b.Found {
		return ""
	}
	switch {
	case b.Logo != "" && b.VMC != "":
		return "BIMI: logo+VMC"
	case b.Logo != "":
		return "BIMI: logo (no VMC)"
	default:
		return "BIMI: present"
	}
}
