package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client simulation matrix — mirrors testssl.sh's `-c / --client-simulation`
// flag. For each named client profile, attempt a TLS handshake using
// that client's cipher list + version range against the target server,
// then report whether the negotiation would succeed and what
// version/cipher would be selected.
//
// Use case: compatibility audit. Before disabling TLS 1.0, before
// removing RSA cipher suites, before locking down to ECDHE-only, you
// want to know: "does Java 8 still work? Does Android 8 still work?
// Does iOS 13 still work?" This check answers that empirically.
//
// Scope: Go's crypto/tls supports TLS 1.0 through 1.3 and the IANA
// cipher suites listed in tls.CipherSuites() / tls.InsecureCipherSuites().
// We simulate any client whose required ciphers are within that set —
// which covers virtually every browser / OS from 2014 onward. Truly
// legacy clients that need RC4-only or 3DES-only handshakes are out of
// scope here (would need a hand-rolled TLS 1.0 client; future work).

// clientProfile is one row in the simulation matrix.
type clientProfile struct {
	Name         string // human-readable identifier
	MinVersion   uint16 // tls.VersionTLS10 / 11 / 12 / 13
	MaxVersion   uint16
	CipherSuites []uint16 // empty = use Go's default for the version range
	Notes        string
}

// simulatedClients is the curated 30-client matrix. Cipher IDs are IANA
// codes; Go's crypto/tls accepts these as uint16 constants.
//
// Selection criteria: highest-impact compatibility audits. Latest stable
// of every major browser (Chrome / Firefox / Safari / Edge); mobile OS
// defaults (Android / iOS); server-runtime clients (Java, .NET, OpenSSL,
// Go); legacy-but-still-deployed (IE 11, Android 4-7).
var simulatedClients = []clientProfile{
	// Latest stable browsers (2026).
	{
		Name:       "Chrome 137 / Win 11",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		Notes: "Chromium-engine browsers (Edge, Brave, Opera) negotiate identically",
	},
	{
		Name:       "Firefox 130 / Linux",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	},
	{
		Name:         "Safari 18 / macOS 15",
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: nil, // Go default — matches modern Safari well enough
		Notes:        "Webkit-based; iOS Safari mirrors closely",
	},
	{
		Name:       "Edge 137 / Win 11",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		Notes: "Chromium-based Edge — same matrix as Chrome",
	},

	// Mobile defaults — modern.
	{
		Name:       "iOS 18 Safari",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	},
	{
		Name:       "iOS 17 Safari",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	},
	{
		Name:       "Android 15 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	},
	{
		Name:       "Android 13 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	},
	{
		Name:       "Android 10 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	},
	{
		Name:       "Android 8.1 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	},
	{
		Name:       "Android 7.0 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	},
	{
		Name:       "Android 5.0 (native)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		Notes: "Old Android; ECDHE+CBC only",
	},

	// JVM clients.
	{
		Name:       "Java 21 (LTS)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	},
	{
		Name:       "Java 17 (LTS)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	},
	{
		Name:       "Java 11 (LTS)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	},
	{
		Name:       "Java 8 u371",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		Notes: "TLS 1.3 backported but disabled by default",
	},

	// .NET clients.
	{
		Name:       ".NET 8 / Win 11",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	},
	{
		Name:       ".NET Framework 4.8 / Win 10",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	},

	// OpenSSL.
	{
		Name:       "OpenSSL 3.4 (modern)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}, // Go default cipher set ≈ OpenSSL modern
	{
		Name:       "OpenSSL 3.0 (Ubuntu 22.04)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	},
	{
		Name:       "OpenSSL 1.1.1 (Ubuntu 20.04 EOL)",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	},
	{
		Name:       "OpenSSL 1.0.2 (legacy)",
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		Notes: "TLS 1.0/1.1 fallback — most CDNs reject by 2026",
	},

	// Go stdlib client.
	{
		Name:       "Go 1.24 net/http client",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	},

	// curl / libcurl.
	{
		Name:       "curl 8.x / OpenSSL 3.x",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	},

	// Older browsers / OSes still deployed in enterprises.
	{
		Name:       "Chrome 49 / Win XP SP3",
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		Notes: "EOL but still seen in industrial / kiosk deployments",
	},
	{
		Name:       "IE 11 / Win 10",
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		Notes: "Hard-coded CBC preference; legacy enterprise",
	},
}

// clientSimulationResult is one row in the report.
type clientSimulationResult struct {
	Client      string `json:"client"`
	Success     bool   `json:"success"`
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// simulateClients runs the full client matrix against the target,
// returning per-client verdicts. Concurrency-limited to 8 parallel
// handshakes to avoid hammering the target.
func simulateClients(host string, port int, sni string, starttlsProto startTLSProtocol, timeout time.Duration) []clientSimulationResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	per := timeout
	if per > 4*time.Second {
		per = 4 * time.Second
	}

	results := make([]clientSimulationResult, len(simulatedClients))

	type job struct {
		idx     int
		profile clientProfile
	}
	jobs := make(chan job, len(simulatedClients))
	done := make(chan struct{}, len(simulatedClients))

	worker := func() {
		for j := range jobs {
			results[j.idx] = simulateOneClient(addr, sni, starttlsProto, j.profile, per)
			done <- struct{}{}
		}
	}

	const parallelism = 8
	for w := 0; w < parallelism; w++ {
		go worker()
	}
	for i, p := range simulatedClients {
		jobs <- job{idx: i, profile: p}
	}
	close(jobs)
	for range simulatedClients {
		<-done
	}
	return results
}

// simulateOneClient performs a single TLS handshake using the given
// client's profile and reports what happened.
func simulateOneClient(addr, sni string, starttlsProto startTLSProtocol, p clientProfile, timeout time.Duration) clientSimulationResult {
	r := clientSimulationResult{Client: p.Name, Notes: p.Notes}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         p.MinVersion,
		MaxVersion:         p.MaxVersion,
		CipherSuites:       p.CipherSuites,
	}

	var conn *tls.Conn
	var err error
	if starttlsProto != "" {
		conn, err = dialSTARTTLS(addr, sni, starttlsProto, cfg, timeout)
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
	}
	if err != nil {
		r.Success = false
		r.Error = tidyErr(err)
		return r
	}
	defer conn.Close()
	st := conn.ConnectionState()
	r.Success = true
	r.Version = tlsVersionName(st.Version)
	r.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	return r
}

// simulateClientsHeadline returns a short summary like
// "Client simulation: 26/28 OK, 2 fail (IE 11, Chrome 49 XP)".
func simulateClientsHeadline(results []clientSimulationResult) string {
	ok := 0
	var fails []string
	for _, r := range results {
		if r.Success {
			ok++
		} else {
			fails = append(fails, r.Client)
		}
	}
	if len(fails) == 0 {
		return fmt.Sprintf("Client simulation: %d/%d compatible ✓", ok, len(results))
	}
	// Sort for stable output.
	sort.Strings(fails)
	preview := fails
	more := 0
	if len(preview) > 3 {
		more = len(preview) - 3
		preview = preview[:3]
	}
	out := fmt.Sprintf("Client simulation: %d/%d compatible — fail: %s",
		ok, len(results), strings.Join(preview, ", "))
	if more > 0 {
		out += fmt.Sprintf(" +%d more", more)
	}
	return out
}
