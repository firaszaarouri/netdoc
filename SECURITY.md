# Security policy

## Reporting a vulnerability

If you discover a vulnerability in netdoc, please report it privately rather than via a public issue.

- Open a [GitHub security advisory](https://github.com/firaszaarouri/netdoc/security/advisories/new) — preferred
- Or email the maintainer directly

Please include:

- The version affected (`netdoc --version`)
- Steps to reproduce
- The impact you observed (information disclosure, crash, RCE, etc.)
- Any proof-of-concept code or sample input that triggers the bug

You will get an acknowledgement within 5 business days. We aim to ship a fix within 30 days for high-severity issues and 90 days for everything else, then publish a CVE alongside the release notes.

## Scope

In scope:

- The `netdoc` binary itself, all subcommands, all flags
- The Go modules under this repository
- The build pipeline (`.goreleaser.yml`, `.github/workflows`)

Out of scope:

- Bugs in upstream dependencies — please report those to their respective projects (`github.com/miekg/dns`, `golang.org/x/crypto`, `github.com/quic-go/quic-go`, etc.)
- Issues with the homebrew tap or scoop bucket — those are packaging concerns
- Findings produced by netdoc when run against third-party targets — those are findings *about* the target, not vulnerabilities *in* netdoc

## Threat model

netdoc is a diagnostic tool that runs as the invoking user with no elevated privileges. It speaks DNS, TCP, UDP, HTTP, and TLS to targets the user specifies. It does not:

- Persist credentials
- Open inbound network listeners
- Modify the local system outside `~/.netdoc/history.jsonl` (and only when `--no-history` is not set)
- Make outbound calls to anything other than the target the user specified

If you find a way to make netdoc do any of the above without explicit user opt-in, that is in scope and we want to hear about it.
