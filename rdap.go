package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// RDAP is the modern WHOIS replacement (RFC 7480-7484, RFC 9082). ICANN
// formally sunsetted the gTLD WHOIS:43 mandate on 2025-01-28; RDAP now
// covers all gTLDs and a growing list of ccTLDs. We use the IANA-published
// bootstrap registry (https://data.iana.org/rdap/dns.json) to find the
// authoritative RDAP server per TLD, then GET /domain/<name>.
//
// Pure stdlib — no new external dependency beyond golang.org/x/net which
// is already pulled in transitively via miekg/dns.

const rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

// rdapBootstrap holds the TLD→server map loaded lazily on first use. The
// bootstrap file is small (~80 KB) and stable; one fetch per netdoc run.
type rdapBootstrap struct {
	once    sync.Once
	err     error
	servers map[string][]string // tld → list of base URLs
}

var rdapDNS = &rdapBootstrap{}

func (b *rdapBootstrap) load(timeout time.Duration) error {
	b.once.Do(func() {
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(rdapBootstrapURL)
		if err != nil {
			b.err = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.err = fmt.Errorf("HTTP %d fetching RDAP bootstrap", resp.StatusCode)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			b.err = err
			return
		}
		var raw struct {
			Services [][][]string `json:"services"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			b.err = err
			return
		}
		m := make(map[string][]string, len(raw.Services)*4)
		for _, svc := range raw.Services {
			if len(svc) < 2 {
				continue
			}
			tlds := svc[0]
			servers := svc[1]
			for _, tld := range tlds {
				m[strings.ToLower(tld)] = servers
			}
		}
		b.servers = m
	})
	return b.err
}

// rdapInfo collects the registration fields netdoc surfaces for a domain.
type rdapInfo struct {
	Domain      string    `json:"domain"`
	Registrar   string    `json:"registrar,omitempty"`
	Status      []string  `json:"status,omitempty"`
	Created     time.Time `json:"created,omitempty"`
	Updated     time.Time `json:"updated,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Nameservers []string  `json:"nameservers,omitempty"`
}

// rdapResponse is the subset of the RFC 7483 object schema netdoc reads.
type rdapResponse struct {
	LdhName     string           `json:"ldhName"`
	Status      []string         `json:"status"`
	Events      []rdapEvent      `json:"events"`
	Entities    []rdapEntity     `json:"entities"`
	Nameservers []rdapNameserver `json:"nameservers"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

type rdapNameserver struct {
	LdhName string `json:"ldhName"`
}

// lookupRDAP locates the authoritative RDAP server for the domain's TLD via
// the IANA bootstrap, then queries /domain/<name>. Falls back through the
// listed servers if the first one errors.
func lookupRDAP(domain string, timeout time.Duration) (rdapInfo, error) {
	if err := rdapDNS.load(timeout); err != nil {
		return rdapInfo{}, fmt.Errorf("bootstrap: %w", err)
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return rdapInfo{}, fmt.Errorf("not a domain: %s", domain)
	}
	tld := parts[len(parts)-1]
	servers := rdapDNS.servers[tld]
	if len(servers) == 0 {
		return rdapInfo{}, fmt.Errorf("no RDAP server for .%s", tld)
	}

	var lastErr error
	for _, server := range servers {
		u := strings.TrimRight(server, "/") + "/domain/" + domain
		r, err := fetchRDAP(u, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		return r, nil
	}
	return rdapInfo{}, lastErr
}

func fetchRDAP(url string, timeout time.Duration) (rdapInfo, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return rdapInfo{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := client.Do(req)
	if err != nil {
		return rdapInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return rdapInfo{}, fmt.Errorf("not registered (RDAP 404)")
	}
	if resp.StatusCode != http.StatusOK {
		return rdapInfo{}, fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return rdapInfo{}, err
	}
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return rdapInfo{}, fmt.Errorf("parse: %w", err)
	}
	out := rdapInfo{Domain: strings.ToLower(strings.TrimSuffix(r.LdhName, ".")), Status: r.Status}
	for _, e := range r.Events {
		t, perr := time.Parse(time.RFC3339, e.Date)
		if perr != nil {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			out.Created = t
		case "last changed", "last update of rdap database":
			out.Updated = t
		case "expiration":
			out.Expires = t
		}
	}
	out.Registrar = registrarFromEntities(r.Entities)
	for _, ns := range r.Nameservers {
		if ns.LdhName != "" {
			out.Nameservers = append(out.Nameservers, strings.ToLower(strings.TrimSuffix(ns.LdhName, ".")))
		}
	}
	return out, nil
}

// registrarFromEntities digs through the entity tree for the one with the
// "registrar" role and pulls its display name out of the vCard.
func registrarFromEntities(entities []rdapEntity) string {
	for _, ent := range entities {
		for _, role := range ent.Roles {
			if strings.EqualFold(role, "registrar") {
				if name := vcardFN(ent.VCardArray); name != "" {
					return name
				}
			}
		}
		if name := registrarFromEntities(ent.Entities); name != "" {
			return name
		}
	}
	return ""
}

// vcardFN extracts the "fn" (full name) string from a vCard array as used in
// RDAP entity records. Schema: ["vcard", [ [name, params, type, value], ... ]].
func vcardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	arr, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, item := range arr {
		line, ok := item.([]any)
		if !ok || len(line) < 4 {
			continue
		}
		if name, _ := line[0].(string); name == "fn" {
			if val, ok := line[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

// checkDomain runs the RDAP lookup and surfaces registration data — when
// the registration was created, when it expires, the registrar, status flags.
// Skips for IP-literal targets and TLDs the bootstrap doesn't cover.
func (d *diagnosis) checkDomain() Check {
	c := Check{Name: "Domain"}
	if d.host == "" {
		c.Status = StatusSkip
		c.Summary = "skipped — no host"
		return c
	}
	if net.ParseIP(d.host) != nil {
		c.Status = StatusSkip
		c.Summary = "skipped — target is an IP literal"
		return c
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(d.host, ".")))
	if err != nil || domain == "" {
		c.Status = StatusSkip
		c.Summary = "skipped — could not derive registrable domain"
		return c
	}

	start := time.Now()
	info, err := lookupRDAP(domain, d.timeout)
	elapsed := time.Since(start)
	if err != nil {
		c.Status = StatusSkip
		c.Summary = "RDAP unavailable — " + tidyErr(err)
		c.Detail = map[string]any{"domain": domain, "error": tidyErr(err), "ms": ms(elapsed)}
		return c
	}
	c.Millis = ms(elapsed)

	detail := map[string]any{
		"domain": info.Domain,
	}
	if info.Registrar != "" {
		detail["registrar"] = info.Registrar
	}
	if len(info.Status) > 0 {
		detail["status"] = info.Status
	}
	if !info.Created.IsZero() {
		detail["created"] = info.Created.Format(time.RFC3339)
	}
	if !info.Updated.IsZero() {
		detail["updated"] = info.Updated.Format(time.RFC3339)
	}
	if !info.Expires.IsZero() {
		detail["expires"] = info.Expires.Format(time.RFC3339)
	}
	if len(info.Nameservers) > 0 {
		detail["nameservers"] = info.Nameservers
	}
	c.Detail = detail

	// Summary text: registered date + age + expires date.
	var bits []string
	if !info.Created.IsZero() {
		years := int(time.Since(info.Created).Hours() / 24 / 365)
		bits = append(bits, fmt.Sprintf("registered %s · %d years old",
			info.Created.Format("2006-01-02"), years))
	}
	expiresStr := ""
	daysLeft := -1
	if !info.Expires.IsZero() {
		daysLeft = int(time.Until(info.Expires).Hours() / 24)
		expiresStr = fmt.Sprintf("expires %s", info.Expires.Format("2006-01-02"))
		bits = append(bits, expiresStr)
	}
	summary := strings.Join(bits, " · ")
	if summary == "" {
		summary = info.Domain + " — registration data present"
	}

	// Build hint line.
	var hintLines []string
	if info.Registrar != "" {
		hintLines = append(hintLines, "registrar: "+truncate(info.Registrar, 44))
	}
	if len(info.Status) > 0 {
		hintLines = append(hintLines, "status: "+truncate(strings.Join(info.Status, " · "), 56))
	}
	c.Hint = strings.Join(hintLines, "\n")

	switch {
	case daysLeft >= 0 && daysLeft < 0:
		// (unreachable — kept symmetric with TLS expiry handling)
		c.Status = StatusFail
		c.Summary = "domain expired"
	case daysLeft >= 0 && daysLeft < 30:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%s (%d day%s left)", summary, daysLeft, plural(daysLeft))
	default:
		c.Status = StatusOK
		c.Summary = summary
	}
	return c
}
