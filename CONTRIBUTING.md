# Contributing to netdoc

Thanks for your interest. This document covers the development setup, the style we follow, and the testing bar a change has to clear.

## Development setup

Requirements:

- Go 1.24 or newer
- Git
- (Optional, for cross-compile testing) `goreleaser` for snapshot builds

```bash
git clone https://github.com/firaszaarouri/netdoc.git
cd netdoc
go build -o netdoc .
go test ./...
```

## Running the smoke tests

```bash
go test ./...                        # all unit tests
go vet ./...                         # static analysis
GOOS=linux GOARCH=amd64 go build .   # cross-compile sanity
GOOS=darwin GOARCH=arm64 go build .
GOOS=windows GOARCH=amd64 go build .
```

Tests cover:

- TLS 1.3 key schedule cross-verified against [RFC 8448](https://datatracker.ietf.org/doc/html/rfc8448) test vectors
- TLS PRF cross-verified against OpenSSL 3.2.1 output
- DNS record parsing (transports, EDE catalog, NSEC3 proof, propagation)
- Mail-posture parsing (SPF, DMARC, DKIM key-strength, RFC 7672 DANE-MX)
- Security-header grading (CSP Level 3 strictness, OWASP compliance)
- DNSBL response classification (RFC 5782 §2.1 valid-answer filter)

## Code style

- **Run `gofmt` before committing.** CI rejects unformatted code.
- **Run `go vet ./...`** — must be clean.
- **Add a test for every behavior change.** Network-touching code can use synthetic inputs; see `tls13_keysched_test.go` for the RFC 8448 pattern.
- **Comments explain *why*, not *what*.** The code shows what; comments capture the constraint, the spec section, the surprise.
- **Match the surrounding style.** This codebase favors small focused functions and explicit error returns over `panic`. No global state beyond the package-level config (`useColor`, `version`).

## What we accept

- **Bug fixes** with a regression test
- **New checks** that fit the unprivileged-single-binary brand (see [the design principles in the README](README.md#design-principles))
- **New service probes** in `services.go` (TCP) or `ports_udp.go` (UDP) — see existing probes for the pattern
- **New DNSBL zones** in `reputation.go` — must include a tier + confidence label
- **Documentation improvements** — `docs/MAIL_SCORING.md` and `docs/SECURITY_HEADERS_RUBRIC.md` are public rubrics; corrections welcome

## What we won't merge (and why)

- **Anything that breaks the unprivileged guarantee.** No SOCK_RAW, no `setcap`, no `sudo` paths in default mode. Privileged features are acceptable behind a clearly-named opt-in flag, never default.
- **Third-party SaaS calls.** No `crt.sh`, no VirusTotal, no Shodan, no telemetry phone-home. Zero-telemetry is a load-bearing brand commitment.
- **Vuln-scanner creep.** No nuclei-style YAML template engine, no payload generator, no exploit framework. netdoc diagnoses; it does not attack.
- **Headless browser dependencies.** No Chromium, no Playwright. The "single binary" promise is non-negotiable.
- **CGO dependencies.** Cross-compile must stay clean from a Go-only toolchain. If you need SQLite, use `modernc.org/sqlite`.

## Pull request checklist

- [ ] Tests pass: `go test ./...`
- [ ] Vet clean: `go vet ./...`
- [ ] Cross-compile clean: Linux + macOS + Windows on amd64 + arm64
- [ ] No new third-party network calls in default code paths
- [ ] Documentation updated if user-visible behavior changed
- [ ] Commit messages explain the *why*, not just the *what*

## Reporting bugs

For non-security bugs, open a [GitHub issue](https://github.com/firaszaarouri/netdoc/issues/new). Include:

- `netdoc --version` output
- The exact command you ran
- The expected vs. actual output
- Your OS and architecture

For security issues, see [SECURITY.md](SECURITY.md) instead — please don't post them in public issues.

## License

By contributing, you agree your contributions will be licensed under the [MIT License](LICENSE) that covers the rest of the project.
