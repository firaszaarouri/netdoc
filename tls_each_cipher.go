package main

import (
	"crypto/tls"
	"sort"
	"sync"
	"time"
)

// Per-cipher enumeration across TLS 1.0 / 1.1 / 1.2. For each codepoint
// in the registry we send one ClientHello offering only that cipher and
// check whether the server completes a ServerHello (accept) or returns
// an alert (reject). 20-deep concurrency pool finishes the ~200-code
// sweep in 5-10 seconds.
//
// Tried an elimination loop first (offer all codes, remove the picked
// one, repeat) — modern servers refuse handshakes that mix historic
// ciphers in one offer. Per-cipher probing sidesteps that entirely.

// eachCipherResult is one row of the --each-cipher enumeration —
// the codepoint, our name for it (if catalogued), the version it
// was accepted at, and its severity classification so downstream
// rendering can flag the broken/weak/policy hits.
type eachCipherResult struct {
	Code       uint16 `json:"code"`
	Name       string `json:"name"`
	Family     string `json:"family,omitempty"`
	Severity   string `json:"severity,omitempty"`
	TLSVersion string `json:"tls_version"`
}

// probeEachCipher enumerates every cipher the server accepts at the
// supplied TLS version by sending one ClientHello per codepoint in
// parallel. Returns the accepted ciphers sorted by severity (broken
// first) so the verdict surfaces the riskiest hits first.
func probeEachCipher(host string, port int, tlsVer uint16, timeout time.Duration) []eachCipherResult {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	allCodes := cipherRegistryAllCodes()
	verName := tlsVersionNameForCode(tlsVer)

	var accepted []eachCipherResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, code := range allCodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(code uint16) {
			defer wg.Done()
			defer func() { <-sem }()
			if !probeOneCipher(host, port, tlsVer, code, timeout) {
				return
			}
			spec := cipherRegistryByCode(code)
			row := eachCipherResult{
				Code:       code,
				TLSVersion: verName,
			}
			if spec != nil {
				row.Name = spec.Name
				row.Family = spec.Family
				row.Severity = spec.Severity
			} else {
				row.Name = cipherCodeName(code)
			}
			mu.Lock()
			accepted = append(accepted, row)
			mu.Unlock()
		}(code)
	}
	wg.Wait()
	return accepted
}

// removeCipherCode (retained for tests) returns a new slice with the
// given codepoint dropped. Originally used by the elimination loop;
// kept for the cipher-set arithmetic tests.
func removeCipherCode(codes []uint16, drop uint16) []uint16 {
	out := codes[:0]
	for _, c := range codes {
		if c != drop {
			out = append(out, c)
		}
	}
	return out
}

// eachCipherAllVersions runs probeEachCipher for TLS 1.0, 1.1, 1.2.
// (TLS 1.3 doesn't use the legacy ClientHello cipher_suites field as
// a negotiation channel — the cipher is signaled via supported_versions
// extension and the cipher_suites field carries the 5 TLS 1.3 IDs.
// Those are enumerated by the existing enumerateCiphers in cipher_enum.go,
// so we skip TLS 1.3 here to avoid double-counting.)
func eachCipherAllVersions(host string, port int, timeout time.Duration) []eachCipherResult {
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	var all []eachCipherResult
	for _, v := range versions {
		all = append(all, probeEachCipher(host, port, v, timeout)...)
	}
	// Sort by TLS version → severity → codepoint for stable output.
	severityOrder := map[string]int{
		"broken": 0, "weak": 1, "policy": 2, "info": 3, "modern": 4, "": 5,
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].TLSVersion != all[j].TLSVersion {
			return all[i].TLSVersion < all[j].TLSVersion
		}
		si, sj := severityOrder[all[i].Severity], severityOrder[all[j].Severity]
		if si != sj {
			return si < sj
		}
		return all[i].Code < all[j].Code
	})
	return all
}

// eachCipherSummary counts hits by severity for the headline.
type eachCipherSummary struct {
	Total    int `json:"total"`
	Broken   int `json:"broken,omitempty"`
	Weak     int `json:"weak,omitempty"`
	Policy   int `json:"policy,omitempty"`
	Modern   int `json:"modern,omitempty"`
	Info     int `json:"info,omitempty"`
	Unknown  int `json:"unknown,omitempty"`
}

func summarizeEachCipher(rows []eachCipherResult) eachCipherSummary {
	s := eachCipherSummary{Total: len(rows)}
	for _, r := range rows {
		switch r.Severity {
		case "broken":
			s.Broken++
		case "weak":
			s.Weak++
		case "policy":
			s.Policy++
		case "modern":
			s.Modern++
		case "info":
			s.Info++
		default:
			s.Unknown++
		}
	}
	return s
}
