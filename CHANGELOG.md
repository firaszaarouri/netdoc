# Changelog

All notable changes to netdoc are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and netdoc follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet. See the [roadmap](#roadmap) below for what's planned.

## [1.0.0] — 2026-05-21

First public release.

### Highlights

- **14-check diagnostic pipeline** in a single unprivileged Go binary against any host
- **Six DNS transports**: system / UDP / TCP / DoT / DoH / DoQ
- **Full-chain DNSSEC validation** from the IANA root anchor; ASCII chain visualizer via `--dnssec-tree`
- **Bit-accurate TLS 1.3 0-RTT detection** via a hand-rolled handshake parsing the raw `NewSessionTicket.early_data` field
- **Cipher enumeration across TLS 1.0/1.1/1.2** for ~190 IANA codepoints via `--each-cipher`
- **SSL Labs A+/A/B/C/D/F TLS grading** with the Feb 2025 rubric (TLS 1.3 absence caps A-, HSTS missing caps A-)
- **Mozilla TLS-profile compliance** (modern / intermediate / old) + OWASP Secure Headers Project compliance
- **3 TLS fingerprints**: JARM + JA3S + JA4S
- **STARTTLS upgrade** for 14 protocols (smtp / lmtp / pop3 / imap / ftp / nntp / xmpp / xmpp-server / sieve / telnet / ldap / irc / mysql / postgres)
- **26-client TLS emulation matrix** (Chrome / Firefox / Safari / Edge / iOS / Android / Java / .NET / OpenSSL / curl / Go / IE / XP-era)
- **CSP Level 3 strictness scoring** — nonces, hashes, strict-dynamic, per-directive findings with severity
- **DKIM key-strength validation** per the 2024 NIST guidance — RSA bit-length, Ed25519, ECDSA
- **DANE for SMTP per RFC 7672** — per-MX TLSA lookup with cert-usage classification
- **Forward-Confirmed reverse DNS (FCrDNS)** check on every resolved IP
- **DNSBL sweep across 116 curated zones** with tier + confidence labels
- **Multi-resolver propagation** view across 13 public recursors
- **Active service probes** for 11 TCP protocols (SSH host-key + KEX, LDAP rootDSE, PostgreSQL, Redis, Elasticsearch, Memcached, MongoDB, SMB2, Telnet, RDP, LDAPS) and 2 UDP (NTP readvar, DNS server.bind CHAOS)
- **Unprivileged ECMP-aware path discovery on Linux** via `IP_RECVERR` (IPv4 TCP-source-port + IPv4 UDP + IPv6 flow-label)
- **nmap -sU-class UDP open / closed / filtered classification** on Linux unprivileged
- **Output formats**: terminal, JSON, HTML, Markdown, `--write-out` template (35+ variables), `--watch` live mode with sparklines, `--diff` against stored baselines
- **Multi-target batch mode** via `-f targets.txt` or multi-positional with JSONL history at `~/.netdoc/history.jsonl`
- **Curated profiles**: `fast` / `web` / `mail` / `full` / `paranoid` via `--profile`
- **Shell completions** for bash, zsh, fish, plus a roff man page

### Distribution

- Linux + macOS + Windows on amd64 + arm64
- `.tar.gz` and `.zip` archives on GitHub Releases
- `.deb` / `.rpm` / `.apk` packages
- Docker images at `ghcr.io/firaszaarouri/netdoc`
- Homebrew tap (`brew install firaszaarouri/netdoc/netdoc`)
- Scoop bucket on Windows

### Honest gaps deferred to future releases

- ARC (RFC 8617) Authenticated Received Chain — requires sending test mail
- testssl-style per-quirk `--bugs` workaround mode for known broken servers
- SSLv2 / SSLv3 handshake probing (would need hand-rolling obsolete crypto)
- Continuous monitoring shape (daemon + persistent storage + dashboards) — a separate product if pursued
- Subdomain enumeration / recon-scale workloads — wrong product shape

## Roadmap

Tracked openly in [GitHub issues](https://github.com/firaszaarouri/netdoc/issues) with the `roadmap` label.

[Unreleased]: https://github.com/firaszaarouri/netdoc/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/firaszaarouri/netdoc/releases/tag/v1.0.0
