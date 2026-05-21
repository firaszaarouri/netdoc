<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo-dark.svg">
    <img src="logo.svg" alt="netdoc" width="320">
  </picture>
</p>

<p align="center"><strong>What's wrong with this host?</strong> netdoc tells you — in one command, in one binary, in two seconds (more or less).</p>

<!-- Project status (live) -->
<p align="center">
  <a href="https://github.com/firaszaarouri/netdoc/releases"><img alt="Release" src="https://img.shields.io/github/v/release/firaszaarouri/netdoc?style=flat-square&color=blue&logo=github&logoColor=white"></a>
  <a href="https://github.com/firaszaarouri/netdoc/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/firaszaarouri/netdoc/ci.yml?style=flat-square&label=CI&logo=githubactions&logoColor=white"></a>
  <a href="https://goreportcard.com/report/github.com/firaszaarouri/netdoc"><img alt="Go Report" src="https://goreportcard.com/badge/github.com/firaszaarouri/netdoc?style=flat-square"></a>
  <a href="LICENSE"><img alt="License MIT" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
  <img alt="Last commit" src="https://img.shields.io/github/last-commit/firaszaarouri/netdoc?style=flat-square&logo=git&logoColor=white">
</p>

<!-- Tech stack -->
<p align="center">
  <img alt="Go 1.24+" src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-supported-FCC624?style=flat-square&logo=linux&logoColor=black">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-supported-000000?style=flat-square&logo=apple&logoColor=white">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-supported-0078D6?style=flat-square&logo=windows&logoColor=white">
  <a href="https://github.com/firaszaarouri/netdoc/pkgs/container/netdoc"><img alt="Docker" src="https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white"></a>
</p>

<!-- Features & guarantees -->
<p align="center">
  <img alt="TLS 1.3" src="https://img.shields.io/badge/TLS-1.3-43A047?style=flat-square&logo=letsencrypt&logoColor=white">
  <img alt="HTTP/3 QUIC" src="https://img.shields.io/badge/HTTP%2F3-QUIC-F29111?style=flat-square">
  <img alt="DNSSEC" src="https://img.shields.io/badge/DNSSEC-validated-7E57C2?style=flat-square">
  <img alt="Mail DMARC + DANE" src="https://img.shields.io/badge/mail-DMARC%20%2B%20DANE-1565C0?style=flat-square&logo=protonmail&logoColor=white">
  <img alt="Zero telemetry" src="https://img.shields.io/badge/telemetry-zero-2E7D32?style=flat-square">
</p>

---

`netdoc` runs fourteen deep network-diagnostic checks — DNS, TLS, HTTP, mail, path, ports, reputation, and more — and prints one verdict naming the first thing to fix.

It replaces what you used to chain together: `dig + delv + curl + openssl + testssl + sslyze + mtr + nmap + MXToolbox + SSL Labs + Hardenize + internet.nl + DNSViz + whatsmydns + securityheaders + …`. One binary, no `sudo`, no Python runtime, no cloud SaaS, no telemetry.

## Contents

- [Why netdoc](#why-netdoc)
- [What makes it different](#what-makes-it-different)
- [At a glance](#at-a-glance)
- [Install](#install)
- [Quick start](#quick-start)
- [What it checks](#what-it-checks)
- [Tutorials](#tutorials)
- [Coverage map — tools netdoc replaces](#coverage-map--tools-netdoc-replaces)
- [Configuration](#configuration)
- [Output formats](#output-formats)
- [FAQ](#faq)
- [Design principles](#design-principles)
- [What netdoc isn't](#what-netdoc-isnt)
- [Building from source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

## Why netdoc

The existing toolchain for diagnosing a hostname looks like this:

```
$ dig +short example.com
$ dig +short MX example.com
$ delv example.com
$ curl -sv https://example.com 2>&1 | head -40
$ openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -noout -dates
$ testssl.sh --quiet example.com
$ mtr -rwc 5 example.com
$ nmap -sV -p 443 example.com
# ...and you've spent twenty minutes and you still need to check SPF/DMARC/DKIM/MTA-STS
```

`netdoc example.com` runs the equivalent of all of that, in one process, in two seconds, with one summary line at the end naming the first problem. Same JSON output across every check, baseline-able with `--diff`, scriptable with `--write-out`, alertable in CI.

Everything happens locally. No `crt.sh` lookups, no SaaS callouts, no API keys, no telemetry. Zero outbound traffic except to the target you specified.

## What makes it different

Plenty of tools cover individual slices of what netdoc does. Eight things make it different in one binary:

### 1. Bit-accurate TLS 1.3 0-RTT detection

Most tools check whether 0-RTT is *possible* (TLS 1.3 + session resumption + appropriate cipher). netdoc hand-rolls a TLS 1.3 client just deep enough to drive the handshake, read the raw post-handshake `NewSessionTicket`, and parse `early_data.max_early_data_size` — the same authoritative value internet.nl reports. Cross-verified against [RFC 8448](https://datatracker.ietf.org/doc/html/rfc8448) test vectors. Live-verified against Cloudflare (`14336`), Facebook (`UINT32_MAX`), Amazon (no 0-RTT).

### 2. Unprivileged ECMP traceroute on Linux

`paris-traceroute` discovers ECMP paths via raw sockets and needs `setcap` or `sudo`. netdoc does the same job using the `IP_RECVERR` socket error queue — the kernel demuxes ICMP errors back to the originating TCP/UDP socket, no raw sockets required. Three backends ship on Linux: IPv4 TCP-source-port ECMP, IPv4 UDP (fallback when ICMP echo is filtered at destination), and IPv6 flow-label ECMP.

### 3. DNSSEC self-validation from embedded IANA root anchors

`dig +dnssec` shows you the `AD` bit but you have to trust your resolver. netdoc embeds the IANA root KSK (key tag 20326 and 38696), walks the chain from root → TLD → registrable-domain → leaf, verifies every DS / DNSKEY / RRSIG itself, and reports the per-zone trust state. Add `--dnssec-tree` to render the validation chain as an ASCII tree.

### 4. CSP Level 3 deep parser with per-directive severity

Most security-headers tools answer "is CSP present?" or "is `unsafe-inline` there?". netdoc parses every directive, applies the Google CSP Evaluator rubric, surfaces critical/high/medium/low findings per directive with concrete remediation suggestions, and detects modern CSP3 escape hatches (nonces, hashes, `'strict-dynamic'`). Public rubric in [`docs/SECURITY_HEADERS_RUBRIC.md`](docs/SECURITY_HEADERS_RUBRIC.md).

### 5. Per-MX DANE for SMTP (RFC 7672)

Hardenize and internet.nl score per-MX DANE deployment. No CLI does. netdoc queries `_25._tcp.<mxhost>` TLSA for every MX, classifies by cert-usage, and only credits records with usage 2 (DANE-TA) or 3 (DANE-EE) — the values RFC 7672 §3.1.3 actually mandates for SMTP. Usage 0/1 records are flagged informationally as "deployed but doesn't confer the PKIX-bypass benefit RFC 7672 intends."

### 6. DKIM key-strength validation per the 2024 NIST guidance

`dig TXT default._domainkey.example.com` tells you the record exists. netdoc fetches every advertised selector, base64-decodes the `p=` field, parses the X.509 SubjectPublicKeyInfo, and reports the actual bit count: RSA (with the 2048+ ideal / 1024+ transitional / <1024 broken classification), Ed25519 (256-bit fixed), ECDSA (curve bits). Revoked selectors (empty `p=`) per RFC 6376 §3.6.1 are detected and flagged.

### 7. `--each-cipher` covers ciphers Go's `crypto/tls` can't natively negotiate

netdoc enumerates ~190 IANA cipher codepoints across TLS 1.0/1.1/1.2 via parallel per-codepoint probes. That includes the obscure families — GOST (Russian), Camellia (Japanese), SEED (Korean KISA-mandated), ARIA, IDEA, RC2, NULL — which Go's standard library doesn't implement. netdoc hand-rolls the TLS 1.2 ClientHello for each one and parses the ServerHello selection (or its `handshake_failure` alert) to detect server acceptance.

### 8. Tier+confidence-labeled DNSBL

Other tools dump a 200-zone result without quality signal — you can't tell a Gmail-rejecting Spamhaus hit from a sketchy regional blocklist. netdoc ships 116 curated zones, each tagged with a tier (composite / spam / exploit / policy / proxy / malware / botnet / tor / dynamic / uri / allowlist / regional / backscatter) and a confidence level (production / operational / heuristic / experimental). Production-grade composite-blocker hits surface as `Fail`; heuristic regional hits surface as `Info`. Plus FCrDNS per IP (the same forward-confirmed reverse-DNS check Gmail/Microsoft/Apple/AWS-SES use to gate inbound).

## At a glance

```
$ netdoc github.com

  netdoc  https://github.com

  ✓  DNS         resolved in 19ms — 1 IPv4, 0 IPv6 · DNSSEC: validated · propagation 13/13 resolvers
  ✓  Domain      registered to GitHub Inc. · expires 2026-10-09 · 4 NS
  ✓  Delegation  com. → github.com. (4 levels)
  ✓  TCP         connected over IPv4 (1/1) on port 443 — fastest 14ms
  ✓  Latency     5 probes: min 12ms · avg 14ms · jitter 2ms · 0% loss
  ✓  Path        14 hops to destination in 13ms · MTU 1469
  ✓  TLS         TLS 1.3 — TLS_AES_128_GCM_SHA256 · ECDSA-P256 · 73d to expiry
                 0-RTT not offered · HSTS preloaded ✓ · JARM 2bc2bc2b…5a1f · Grade A+
  ✓  HTTP        HTTP/2 200 OK — TTFB 54ms · HTTP/3 confirmed via QUIC
  ✓  Security    87/100 (B) — 11 of 12 headers pass · CSP strict (90/100) · OWASP ✓
  ✓  Discovery   security.txt · OIDC issuer
  ✓  Mail        SPF -all · DMARC p=reject · DKIM ✓ · MTA-STS enforce · TLS-RPT ✓
  ✓  Reputation  clean across 116 blocklists (1 IP) — FCrDNS ✓
  ·  IPv6        no IPv6 — host has no AAAA record
  ✓  Ports       skipped (use --ports to enable)

  ✓ Healthy — no problems found   (1.4s)
```

When something is broken, the output names what to fix first:

```
$ netdoc expired.badssl.com

  ✗  TLS    certificate problem — x509: certificate has expired (188 days ago)
  ✗  HTTP   request failed: tls: failed to verify certificate
  ...
  ✗ 2 problems found
  → Fix first: TLS — certificate expired 2024-11-12
```

## Install

### Pre-built binaries

Each tagged release publishes binaries for Linux, macOS, and Windows on both amd64 and arm64:

- **GitHub Releases** — [download the archive for your platform](https://github.com/firaszaarouri/netdoc/releases/latest)
- **Homebrew** (macOS, Linux): `brew install firaszaarouri/netdoc/netdoc`
- **Scoop** (Windows): `scoop bucket add netdoc https://github.com/firaszaarouri/scoop-netdoc.git && scoop install netdoc`
- **Debian / Ubuntu**: download the `.deb` from the latest release, then `sudo dpkg -i netdoc_*.deb`
- **RHEL / Fedora / openSUSE**: download the `.rpm` from the latest release, then `sudo rpm -i netdoc-*.rpm`
- **Alpine**: download the `.apk` and `sudo apk add --allow-untrusted netdoc-*.apk`
- **Docker**: `docker run --rm ghcr.io/firaszaarouri/netdoc:latest github.com`

Checksums (`checksums.txt`) are published with every release; verify with `sha256sum -c`.

### From source

Requires Go 1.24 or newer.

```bash
git clone https://github.com/firaszaarouri/netdoc.git
cd netdoc
go build -o netdoc .
./netdoc --version
```

Or directly via `go install`:

```bash
go install github.com/firaszaarouri/netdoc@latest
```

## Quick start

```bash
netdoc github.com                                # the everyday command
netdoc https://api.example.com                   # full URL forms accepted
netdoc example.com:8443                          # explicit port
netdoc 8.8.8.8                                   # IP literal (domain/mail skip cleanly)

netdoc cloudflare.com                            # 0-RTT detection, full TLS posture
netdoc gmail.com                                 # mail posture with DANE-MX + FCrDNS
netdoc expired.badssl.com                        # see how broken endpoints render

netdoc github.com --json | jq '.healthy'         # CI-friendly (exit 1 on any problem)
netdoc github.com --watch                        # live mode with per-metric sparklines
netdoc github.com --ports top1000                # nmap top-1000 TCP scan
netdoc -f targets.txt --concurrency 8            # batch mode against a fleet
```

## What it checks

| # | Check | Coverage |
|---|---|---|
| 1 | **DNS** | A/AAAA/MX/NS/TXT/CNAME/PTR/SRV/CAA/HTTPS/SVCB · full-chain DNSSEC self-validation from IANA root anchors · NSID · transports: system / UDP / TCP / DoT / DoH / DoQ · CHAOS queries against every NS · 13-resolver propagation · AXFR · glue + lame detection · NSEC3 proof + NSEC walk · DNS Cookies (RFC 7873) · DNSSEC algorithm rollover · EDNS Client-Subnet probe · RPKI per-prefix |
| 2 | **Domain** | RDAP lookup via IANA bootstrap — registrar, dates, status, name servers, vCard |
| 3 | **Delegation** | root → TLD → authoritative walk |
| 4 | **TCP** | connect to every resolved IP (v4 + v6) on the target port |
| 5 | **Latency** | 5 probes, min/avg/max/jitter/loss · ICMP-then-TCP fallback · DF-bit Path-MTU binary search |
| 6 | **Path** | TTL 1..30 traceroute with 3 probes per TTL aggregated for min/avg/max/jitter/loss · per-hop ASN · Path-MTU · on Linux: 4 unprivileged backends (ICMP + IPv6 flow-label ECMP + IPv4 TCP-source-port ECMP + IPv4 UDP fallback when ICMP filtered) |
| 7 | **TLS** | handshake + full cert chain (SAN, key alg+bits, sig alg, serial, SHA-256 fp, Must-Staple, wildcard) · OCSP + CRL · embedded SCTs (31-entry CT log map) · cipher enumeration per TLS version with A/B/C/F grade · `--each-cipher` for ~190-codepoint IANA-registry sweep · cipher preference order · ALPN enumeration · DANE/TLSA · EMS (RFC 7627) · RFC 5746 secure-renegotiation · DH parameter + Logjam common-prime DB · ECH detection via HTTPS SVCB · JARM + JA3S + JA4S · PQC X25519MLKEM768 · CBC oracle variants (GOLDENDOODLE / Zombie / Sleeping POODLE) · ROBOT · Ticketbleed · BREACH · STARTTLS Injection · Winshock · client-init reneg DoS · obscure ciphers (GOST/Camellia/SEED/ARIA/IDEA) · bit-accurate TLS 1.3 0-RTT via hand-rolled handshake · Mozilla profile compliance · 26-client emulation matrix · SSL Labs A+/A/B/C/D/F grade · STARTTLS for 14 protocols |
| 8 | **HTTP** | H1/H2 + real HTTP/3 over QUIC · full redirect chain · HSTS · body throughput · time-skew · OPTIONS sweep with risky-verb detection · CORS misconfig probe · Server-Timing parser · SRI + mixed-content + insecure-form + unsandboxed-iframe scan via `golang.org/x/net/html` |
| 9 | **Security** | 12-header grader (HSTS preload-eligibility, CSP, XFO, XCTO, Referrer, Permissions, COOP, COEP, CORP, Origin-Agent-Cluster, Document-Policy, Reporting-Endpoints) → 0-100 + letter · CSP Level 3 deep parser with per-directive findings + severity · cookie audit · deprecated + info-leak header detection · OWASP Secure Headers Project compliance · embedded HSTS preload Chromium DB lookup — see [`docs/SECURITY_HEADERS_RUBRIC.md`](docs/SECURITY_HEADERS_RUBRIC.md) |
| 10 | **Discovery** | concurrent `/.well-known/` probes: OIDC, OAuth-AS, security.txt, change-password, WebAuthn, Apple passkey, SAML metadata, WebTransport, host-meta · WWW-Authenticate scheme detection |
| 11 | **Mail** | SPF + DMARC + DKIM-selector + DKIM key-strength (RSA/Ed25519/ECDSA bit-length per 2024 NIST guidance) + MTA-STS + TLS-RPT + STARTTLS-on-every-MX + BIMI + DMARC RUA/RUF external-destination authorization (RFC 7489 §7.1) + DANE for SMTP per RFC 7672 + IPv6-MX presence + reachability · 7-dimension 0-100 score — see [`docs/MAIL_SCORING.md`](docs/MAIL_SCORING.md) |
| 12 | **Reputation** | DNSBL sweep across 116 curated zones with tier + confidence labels (production / operational / heuristic / experimental) · Forward-Confirmed reverse DNS (FCrDNS) per IP per RFC 8499 §3 · RFC 5782 §2.1 sentinel filtering |
| 13 | **IPv6** | AAAA presence + reachability + local-network attribution |
| 14 | **Ports** (opt-in via `--ports`) | TCP-connect scan + banner-grab + service regex · 11 active TCP probes (SSH host-key + KEX, LDAP rootDSE, PostgreSQL, Redis, Elasticsearch, Memcached, MongoDB, LDAPS, SMB2 NEGOTIATE, Telnet IAC, RDP X.224) · 2 active UDP probes (NTP mode-6 readvar, DNS server.bind CHAOS) · Linux IP_RECVERR-based UDP open/closed/filtered classifier (nmap -sU class, unprivileged) |

## Tutorials

### 1. Audit a production endpoint

```bash
netdoc api.example.com
```

The default output is the audit. Everything is there: DNS, TLS, HTTP, mail, security headers, reputation. The trailing "Fix first" line names the highest-priority finding so you know where to start. Exit code `0` = healthy, `1` = problem(s) found, `2` = bad usage.

### 2. Debug a mail-server posture

```bash
netdoc --check mail example.com
# Or for just the records, no scoring:
netdoc example.com --json | jq '.checks[]|select(.name=="Mail").detail'
```

The Mail check covers SPF, DMARC, DKIM (with key-strength validation), MTA-STS, TLS-RPT, BIMI, DMARC RUA/RUF external-destination authorization (RFC 7489 §7.1), DANE-MX (RFC 7672), and IPv6-MX. The 7-dimension rubric is documented in [`docs/MAIL_SCORING.md`](docs/MAIL_SCORING.md). Per-MX TLS posture is collected separately in the TLS check's `--starttls` modes for 14 protocols.

### 3. TLS deep-dive on a hardened endpoint

```bash
netdoc --check tls cloudflare.com
netdoc --check tls --each-cipher cloudflare.com       # ~190-codepoint IANA sweep
netdoc --check tls --cipher-pattern RC4 example.com   # any RC4 cipher offered?
netdoc -t smtp mail.example.com                       # STARTTLS upgrade to SMTP, then full TLS audit
```

The TLS check produces the full A+/A/B/C/D/F grade with the Feb 2025 SSL Labs rubric (TLS 1.3 absence caps A-, HSTS missing caps A-). For deeper introspection, `--each-cipher` runs per-codepoint probes across TLS 1.0/1.1/1.2 in parallel and reports every cipher the server actually accepts — including obscure GOST/Camellia/SEED/ARIA/IDEA suites Go's `crypto/tls` won't negotiate natively.

### 4. CI integration

```bash
# Block deploys if TLS regresses below A
netdoc --check tls --json prod.example.com | jq -e '.checks[]|select(.name=="TLS").detail.grade|IN("A","A+")'

# Diff against a known-good baseline
netdoc --json prod.example.com > baseline.json
# (later, in CI:)
netdoc --json prod.example.com --diff baseline.json
# exit code 1 on any drift; the report names what changed

# curl-style scriptable output
netdoc example.com --write-out '${time_total},${grade},${jarm}\n'
```

Every check writes to the same JSON shape — `.checks[].name`, `.checks[].status`, `.checks[].detail` — so you can pipe through `jq`, alert on specific findings, or store in your time-series database.

### 5. Multi-target fleet monitoring

```bash
# Newline-delimited file of hosts
netdoc -f targets.txt --concurrency 8 --json > fleet.jsonl

# Or multi-positional
netdoc a.example.com b.example.com c.example.com --json

# History — every scan appends to ~/.netdoc/history.jsonl
netdoc github.com           # appends
netdoc github.com --history # show last 10 scans
netdoc github.com --no-history  # don't append this one
```

### 6. Live mode with sparklines

```bash
netdoc --watch github.com
netdoc --watch=2s github.com    # 2-second tick
netdoc --interval 10s --watch github.com
```

Each metric (latency, TTFB, throughput, etc.) gets its own sparkline ring buffer. Useful during deploys or while debugging a flapping endpoint.

### 7. Force a specific DNS transport

```bash
netdoc github.com --dns doq                                       # DNS-over-QUIC (RFC 9250)
netdoc github.com --dns doh:https://cloudflare-dns.com/dns-query
netdoc github.com --dns dot:1.1.1.1
netdoc github.com --dns tcp                                       # forced TCP-53
```

### 8. Profiles for common scopes

```bash
netdoc --profile fast example.com         # sub-second posture (skips RDAP, path, mail)
netdoc --profile web example.com          # HTTP-focused, no mail
netdoc --profile mail example.com         # mail-focused, no HTTP
netdoc --profile paranoid example.com     # everything, including --ports top1000
```

## Coverage map — tools netdoc replaces

If you currently chain any of these together, netdoc covers the same ground in one binary. The dedicated tools are excellent at what they do — the point is that you stop needing to install, learn, and chain six of them when one suffices.

| Diagnostic task | Tools you might use today | netdoc coverage |
|---|---|---|
| **DNS records + transports** | `dig`, `kdig`, `delv`, `doggo`, `q`, `drill` | A/AAAA/MX/NS/TXT/CNAME/PTR/SRV/CAA/HTTPS/SVCB across system/UDP/TCP/DoT/DoH/DoQ |
| **DNSSEC validation** | `delv`, `unbound-anchor`, `dnssec-verify`, DNSViz | full-chain self-validation from IANA root anchors; `--dnssec-tree` for ASCII chain visualization |
| **DNSSEC visualization** | DNSViz (graphviz PNG/SVG) | `--dnssec-tree` ASCII chain in the DNS check |
| **Multi-resolver propagation** | whatsmydns.net (SaaS) | 13 public recursors, locally |
| **Domain registration** | `whois`, `rdap-client` | RDAP via IANA bootstrap |
| **Path discovery** | `traceroute`, `mtr`, `paris-traceroute`, `tcptraceroute`, `trippy` | 4 unprivileged backends on Linux (ICMP + IPv6 flow-label + IPv4 TCP-source-port + IPv4 UDP); 3 probes per TTL; per-hop ASN; Path-MTU |
| **TCP handshake + Latency** | `nc`, `tcpping`, `httping` | TCP connect + 5-probe latency with jitter/loss |
| **Port scan + service ID** | `nmap`, `nmap -sV`, `naabu`, `rustscan` | TCP-connect with banner-grab + 11 active service probes + 2 active UDP probes + Linux IP_RECVERR UDP open/closed/filtered (unprivileged) |
| **TLS handshake + CVE probes** | `openssl s_client`, `testssl.sh`, `sslyze` | 20+ posture probes + Heartbleed/ROBOT/CCS/BEAST/CRIME/BREACH/SWEET32/POODLE/Logjam/FREAK/DROWN/STARTTLS-Injection + Mozilla compliance |
| **TLS 1.3 0-RTT detection** | internet.nl (SaaS) | bit-accurate, parsing the raw `NewSessionTicket.early_data.max_early_data_size` via hand-rolled handshake |
| **Cipher enumeration** | `sslyze`, `sslscan`, `testssl.sh --each-cipher` | per-version A/B/C/F + preference order + `--each-cipher` ~190-codepoint IANA sweep |
| **TLS fingerprinting** | JARM tools, `tlsx` (ProjectDiscovery) | JARM + JA3S + JA4S in one pass |
| **STARTTLS upgrades** | `testssl.sh -t`, `swaks` | 14 protocols: smtp/lmtp/pop3/imap/ftp/nntp/xmpp/xmpp-server/sieve/telnet/ldap/irc/mysql/postgres |
| **DANE for SMTP** | DNSViz, custom scripts | per-MX TLSA lookup with RFC 7672 cert-usage classification |
| **HTTP/1.1 + HTTP/2** | `curl`, `httpie` | full redirect chain + body throughput + HSTS + time-skew |
| **Real HTTP/3 over QUIC** | `curl --http3` | real QUIC handshake via `quic-go` |
| **curl-style write-out** | `curl --write-out` | `--write-out` with 35+ variables (`${time_total}`, `${grade}`, `${jarm}`, `${spf}`, ...) |
| **Security header grading** | securityheaders.com (SaaS), Mozilla Observatory | 12-header grader + CSP Level 3 deep parser with per-directive findings — documented in [`docs/SECURITY_HEADERS_RUBRIC.md`](docs/SECURITY_HEADERS_RUBRIC.md) |
| **Mail-posture audit** | internet.nl (SaaS), Hardenize (SaaS), MXToolbox (SaaS), `checkdmarc` | SPF + DMARC + DKIM key-strength + MTA-STS + TLS-RPT + STARTTLS-per-MX + BIMI + DMARC RUA external auth + DANE-MX + IPv6-MX — 7-dimension score documented in [`docs/MAIL_SCORING.md`](docs/MAIL_SCORING.md) |
| **DNSBL / IP reputation** | MXToolbox (SaaS), MultiRBL.valli.org, `rblcheck` | 116 zones with tier + confidence labels + FCrDNS check per IP |
| **/.well-known discovery** | manual `curl /.well-known/...` | OIDC, OAuth-AS, security.txt, change-password, WebAuthn, Apple passkey, SAML metadata, WebTransport, host-meta |
| **Mass scan / recon** | `masscan`, `zmap`, `subfinder`, `amass` | out of scope — see [What netdoc isn't](#what-netdoc-isnt) |

## Configuration

### Flags

| Flag | Effect |
|---|---|
| `--json` | structured JSON report covering every check + every detail field |
| `--format <fmt>` | output format: `json` / `html` / `md` / `markdown` |
| `--timeout <dur>` | per-check timeout, default `5s` |
| `--dns <spec>` | DNS transport: `system` (default) / `udp` / `tcp` / `dot` / `doh` / `doq`, optionally followed by `:server` (e.g. `dot:1.1.1.1`) |
| `--ports <spec>` | comma-separated ports, range `1-1024`, or presets `top20` / `top100` / `top1000` |
| `--ecs [<cidr>]` | EDNS Client-Subnet probe — bare flag uses the 5-continent default (US/DE/JP/BR/AU), or pass a CIDR (comma-list accepted) |
| `--check <list>` | run only the named checks (comma-separated). Valid: `dns`, `domain`, `delegation`, `tcp`, `latency`, `path`, `tls`, `http`, `security`, `discovery`, `mail`, `reputation`, `ipv6`, `ports` |
| `--profile <name>` | curated check preset: `fast` / `web` / `mail` / `full` / `paranoid` |
| `-t, --starttls <protocol>` | upgrade a plaintext connection via STARTTLS before the TLS audit. Valid: `smtp` / `lmtp` / `pop3` / `imap` / `ftp` / `nntp` / `xmpp` / `xmpp-server` / `sieve` / `telnet` / `ldap` / `irc` / `mysql` / `postgres` |
| `-x, --cipher-pattern <pat>` | filter cipher enumeration by name fragment, IANA name, or hex codepoint (e.g. `--cipher-pattern RC4` or `-x 0xc02f`) |
| `--each-cipher` | enumerate every cipher the server accepts across TLS 1.0/1.1/1.2 via per-codepoint probes |
| `--dnssec-tree` | render the DNSSEC validation chain as an ASCII tree in the DNS check's hint |
| `--diff <baseline.json>` | structural diff against a stored Report; exit `1` on any drift |
| `--write-out <fmt>` | curl-style format template with 35+ variables |
| `--watch [=dur]` | live re-running mode with per-metric sparkline ring buffers (default `5s` tick) |
| `--interval <dur>` | set the `--watch` interval explicitly |
| `-f, --file <path>` | batch mode — read newline-delimited targets from path (or `-` for stdin) |
| `--concurrency <n>` | batch parallelism (default `8`) |
| `--history [N]` | show last `N` scans (default 10) for the given target from `~/.netdoc/history.jsonl` |
| `--no-history` | skip appending this scan to history |
| `--no-color` / `NO_COLOR=1` | disable color output |
| `-v, --version` | print version |
| `-h, --help` | print help |
| `--help-flags` | one-flag-per-line compact list (for shell-completion authors and `grep` pipelines) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Healthy — every check passed |
| `1` | At least one check failed, OR `--diff` detected drift, OR batch mode found any unhealthy target |
| `2` | Usage error — unrecognized flag, malformed argument, missing target |

### Shell completions

Tab-completion is shipped for bash, zsh, and fish in `completions/`. Installation depends on your shell — see the file headers for the per-shell incantation.

### Man page

The roff source lives at `man/netdoc.1`. Install with `cp man/netdoc.1 /usr/local/share/man/man1/ && mandb` (Linux) or the equivalent on your platform.

## Output formats

The same data is available in five rendering modes:

| Format | Flag | Use case |
|---|---|---|
| **Terminal** | (default) | day-to-day human use, colorized, with timing chart |
| **JSON** | `--json` or `--format json` | scripts, CI, alerts; one object per Report, every detail field present |
| **HTML** | `--format html` | single-file report for tickets / Slack / email — embedded styles, dark-mode aware |
| **Markdown** | `--format md` | paste into a GitHub issue, PR, or runbook |
| **`--write-out`** | `--write-out '<tpl>'` | curl-style scriptable template with 35+ variables |
| **`--watch`** | `--watch` | live mode, redrawn in place, with sparkline ring buffers |

## FAQ

**Why would I use netdoc instead of `testssl.sh` / `sslyze` / `dig` / `nmap`?**
Use those when you only care about *one* of TLS, DNS, or ports. Use netdoc when you want all of them at once with a single verdict naming the first thing to fix. The dedicated tools are excellent at their slice; netdoc consolidates them into one investigation flow. The TLS-specific depth in netdoc covers what testssl/sslyze cover plus things they don't (bit-accurate 0-RTT, JA4S, RFC 7672 DANE-MX, BREACH, STARTTLS Injection, Winshock inference) — but if you only need TLS, testssl/sslyze remain great choices.

**Does it phone home? Talk to crt.sh? VirusTotal? Shodan?**
No. Zero outbound traffic except to the target you specified. No analytics, no telemetry, no API keys, no SaaS callouts. The only network destinations netdoc contacts are DNS resolvers (you can override with `--dns`), the target hostname, and Team Cymru's DNS-based ASN service (`*.origin.asn.cymru.com`) for per-IP ASN annotation. Everything else is hand-rolled locally.

**Does it need `sudo`?**
No. Default operation is fully unprivileged. ICMP on Linux uses `SOCK_DGRAM` (the unprivileged path), ECMP discovery on Linux uses `IP_RECVERR` instead of raw sockets. The only operations that would require privileges (Windows IPv6 flow-label, macOS IPv4 TCP-source-port traceroute) are stubbed on those platforms rather than silently degraded.

**Is it production-ready?**
The protocol implementations are RFC-test-vector verified (TLS 1.3 key schedule against RFC 8448, TLS PRF against OpenSSL 3.2.1) and the codebase ships with a full test suite. Use it. If you find a bug, [open an issue](https://github.com/firaszaarouri/netdoc/issues) — security issues should go to [SECURITY.md](SECURITY.md).

**How accurate is the SSL Labs A+/A/B/C/D/F grade?**
It follows the [SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide) with the Feb 2025 revision applied: TLS 1.3 absence caps the grade at A-; HSTS missing caps A-; RC4 caps B; weak DH caps B; SSLv3/TLS 1.0/1.1 cap C. The full rubric is exposed in JSON `detail.grade` so you can recompute it yourself if you disagree with the weights.

**Can I baseline a host and alert on drift?**
Yes. `netdoc --json host.example.com > baseline.json`, then later `netdoc --json host.example.com --diff baseline.json`. Exit code 1 on any structural drift; the report names what changed. Good for CI gates.

**What's the binary size? Memory footprint?**
About 14 MB (stripped: 10 MB). RAM footprint is dominated by the TLS state during cipher enumeration — typically under 30 MB peak, even for `--each-cipher` against a TLS-1.0-supporting target.

**Does it support proxies?**
HTTPS_PROXY / HTTP_PROXY environment variables are respected for HTTP probes. TLS / DNS / TCP probes connect directly — proxying them would defeat the diagnostic.

**Is there a long-running daemon / web UI?**
Not built in. netdoc is a one-shot CLI by design. The JSONL history at `~/.netdoc/history.jsonl` is the closest it gets to state. If you want trending dashboards, pipe `--json` output into your existing observability stack (Prometheus, ClickHouse, Loki — they all accept JSON line streams).

**Why is the test suite tied to RFC 8448?**
The hand-rolled TLS 1.3 client used for 0-RTT detection only works if every primitive (HKDF-Expand-Label, derive-secret, the four early/handshake/application traffic secrets) matches the spec bit-for-bit. RFC 8448 publishes test vectors precisely so implementations can self-verify. We use them as the canonical regression test — if RFC 8448 §3 passes, the TLS 1.3 stack is correct.

**Will you add subdomain enumeration / OSINT / vuln exploitation?**
No. See [What netdoc isn't](#what-netdoc-isnt) for the scope decisions and the reasoning. Different tools, different shape. Use `amass` / `subfinder` for recon; use `nuclei` / Metasploit for exploitation.

## Design principles

These are explicit commitments, not aspirations:

1. **Unprivileged by default.** No `sudo`, no `setcap`, no Administrator. If a feature genuinely requires raw sockets (Windows IPv6 flow-label, macOS IPv4 TCP-source-port traceroute), it's stubbed, documented, and we ship the other platforms only — never silently degraded.
2. **Single binary, no external runtime.** No Chromium, no Python, no Node, no CGO. Cross-compiles cleanly to Linux + macOS + Windows on amd64 + arm64. ~14 MB.
3. **Zero telemetry, zero SaaS.** No phone-home. No `crt.sh` lookups, no VirusTotal, no Shodan, no external API by default. The only outbound traffic goes to the target you specified.
4. **Bit-accurate where possible.** Hand-rolled TLS 1.3 for 0-RTT detection because Go's `crypto/tls` hides the data; cross-verified against [RFC 8448](https://datatracker.ietf.org/doc/html/rfc8448) test vectors. PRF cross-verified against OpenSSL 3.2.1.
5. **Public scoring rubrics.** Every grade (TLS A+/A/B/C/D/F, Security 0-100, Mail 0-100, CSP strictness) is documented in `docs/`. No black-box scoring.
6. **Diagnostic, not pentest.** netdoc identifies problems; it does not exploit them. No YAML template engine, no nuclei-style payload library, no headless browser, no exploit framework.

## What netdoc isn't

(These are intentional scope decisions, not "missing features".)

- ❌ **Subdomain enumeration / recon-scale workloads** — different problem shape. Use `amass`, `subfinder`, `assetfinder`.
- ❌ **Mass / sweep scanning** — single-target focus. Multi-target batch mode exists but isn't designed for internet-wide scanning. Use `masscan` or `zmap`.
- ❌ **Vulnerability exploitation** — diagnostic only. netdoc detects ROBOT; it doesn't run a Bleichenbacher attack to extract the key.
- ❌ **Stealth scan modes** — kills the unprivileged guarantee. Use `nmap` with raw sockets.
- ❌ **Cloud-account access** — never asks for AWS/GCP/Azure credentials.
- ❌ **Continuous monitoring / dashboards** — netdoc is a one-shot CLI. JSONL history at `~/.netdoc/history.jsonl` is the closest it gets to state.

## Building from source

Requires Go 1.24 or newer.

```bash
git clone https://github.com/firaszaarouri/netdoc.git
cd netdoc
go build -o netdoc .
go vet ./...
go test ./...
```

Cross-compile for other platforms:

```bash
GOOS=linux   GOARCH=amd64 go build -o netdoc-linux-amd64   .
GOOS=linux   GOARCH=arm64 go build -o netdoc-linux-arm64   .
GOOS=darwin  GOARCH=amd64 go build -o netdoc-darwin-amd64  .
GOOS=darwin  GOARCH=arm64 go build -o netdoc-darwin-arm64  .
GOOS=windows GOARCH=amd64 go build -o netdoc-windows-amd64.exe .
```

Local goreleaser dry-run (requires `goreleaser` installed):

```bash
goreleaser release --snapshot --clean --skip-publish
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the testing bar, and what we will / won't merge.

Security issues should not be filed as public issues — see [SECURITY.md](SECURITY.md) for the disclosure process.

## Author

**[Firas Zaarouri](https://github.com/firaszaarouri)**
MSc Data Analytics · MEng General Engineering · PhD Candidate
LIP6, Sorbonne Université — NPA Team

## License

[MIT](LICENSE)
