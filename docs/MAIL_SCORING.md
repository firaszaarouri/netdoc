# netdoc — mail-posture scoring rubric

netdoc grades a domain's mail-receiving posture across seven dimensions
informed by [internet.nl](https://internet.nl)'s scoring (the EU-wide
de-facto baseline since the NCSC Mail Check shutdown in March 2026) plus
[Red Sift Hardenize](https://www.hardenize.com)'s Email Infrastructure
policy. The rubric below is the exact algorithm `checkMail()` runs in
[mail.go](../mail.go) — public, documented, reproducible.

## Score (0 – 100)

The seven weights sum to exactly 100. A fully-deployed posture scores
100; a domain with no mail records at all scores 0.

| Weight | Dimension                  | Pass criterion                                                                   |
| -----: | -------------------------- | -------------------------------------------------------------------------------- |
|     20 | **SPF**                    | terminal `-all` → full 20; `~all` (softfail) → 12; missing / `?all` / `+all` → 0 |
|     20 | **DMARC**                  | `p=reject` → 20; `p=quarantine` → 12; `p=none` → 5; missing → 0                  |
|     15 | **DKIM key strength**      | ≥1 selector with strong key (RSA ≥1024 transitional, ≥2048 ideal, Ed25519) → 15; weak (<1024) → 5; no DKIM → 0 |
|     15 | **MTA-STS**                | `mode=enforce` → 15; `mode=testing` → 8; missing → 0                              |
|     10 | **TLS-RPT**                | `_smtp._tls.<domain>` TXT present → 10                                            |
|     10 | **DANE-MX**                | ≥1 MX has TLSA record at `_25._tcp.<mxhost>` with cert usage 2 (DANE-TA) or 3 (DANE-EE) per RFC 7672 |
|     10 | **IPv6-MX**                | ≥1 MX has an AAAA record                                                          |
| **100** | **Total**                  |                                                                                   |

### Letter grades

| Score   | Grade |
| ------: | :---: |
| 90 –100 | **A** |
| 80 – 89 | **B** |
| 70 – 79 | **C** |
| 60 – 69 | **D** |
| < 60    | **F** |

The check returns `StatusOK` when score ≥ 80, `StatusWarn` otherwise.
There is no `StatusFail` — every finding is a hardening opportunity,
not a runtime failure.

## Dimension details

### 1. SPF (RFC 7208)

Looked up at the apex domain's TXT record. We parse mechanisms and the
terminal directive:

- **`-all`** (Hardfail): All non-authorized sources MUST be rejected.
  Strongest signal — full 20 points.
- **`~all`** (Softfail): Mail SHOULD be accepted with a flag.
  Acceptable but weaker — 12 points.
- **`?all`** (Neutral) / **`+all`** (Pass-all) / missing: No protection.
  0 points.

netdoc additionally tracks the SPF mechanism count (RFC 7208 §4.6.4
limits to 10 DNS lookups) and surfaces a warning when the count
approaches the limit.

### 2. DMARC (RFC 7489 + RFC 9091)

Looked up at `_dmarc.<domain>` TXT record.

- **`p=reject`**: Receivers MUST reject failed messages → full 20.
- **`p=quarantine`**: Receivers SHOULD spam-folder failed messages → 12.
- **`p=none`**: Monitoring-only — no enforcement → 5 (we credit
  the deployment effort but flag it as incomplete).
- Missing → 0.

netdoc additionally validates the RUA/RUF external-destination
authorization per RFC 7489 §7.1 — surfaced in the hint.

### 3. DKIM key strength (RFC 6376 + 2024 NIST guidance)

For every advertised selector (probed across the common list:
google, selector1, default, k1, dkim, mail, etc.) we:

1. Resolve `<selector>._domainkey.<domain>` TXT.
2. Parse the `p=` field as a base64 X.509 SPKI.
3. Extract algorithm + bit length.

Grading:

| Algorithm   | Bits          | Verdict                                  |
| ----------- | ------------- | ---------------------------------------- |
| RSA         | ≥ 2048        | strong (ideal)                           |
| RSA         | 1024 – 2047   | strong (transitional — recommend ≥2048)  |
| RSA         | < 1024        | weak                                     |
| Ed25519     | 256 (fixed)   | strong                                   |
| ECDSA       | ≥ 256         | strong                                   |
| revoked     | empty `p=`    | flagged as revoked (RFC 6376 §3.6.1)     |
| malformed   | any           | flagged in the reason field              |

≥1 strong-key selector → full 15 points.
≥1 weak-key selector with no strong selector → 5 points (we credit
the deployment but flag the key strength).
No DKIM advertised → 0.

### 4. MTA-STS (RFC 8461)

Looked up at `_mta-sts.<domain>` TXT (the indicator record) plus a
fetch of `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

- **`mode: enforce`**: 15 — receiver MUST refuse non-STS-compliant
  connections.
- **`mode: testing`**: 8 — receiver SHOULD report violations but
  accept the mail; the policy is being soft-rolled.
- Missing → 0.

netdoc additionally parses the MX list in the policy file and
warns when it diverges from the live MX RRset (a common misconfig).

### 5. TLS-RPT (RFC 8460)

Looked up at `_smtp._tls.<domain>` TXT.

- Present with a parseable `rua=` endpoint → 10.
- Missing → 0.

We don't currently grade the rua= endpoint validity (mailto: vs
https:); this is on the roadmap.

### 6. DANE-MX (RFC 7672)

For each MX hostname, we look up `_25._tcp.<mxhost>` TLSA. RFC 7672
mandates that SMTP DANE implementations MUST use cert usage:

| Usage | Name      | RFC 7672-compliant for SMTP? |
| ----: | --------- | :--------------------------: |
|     0 | PKIX-TA   |             no               |
|     1 | PKIX-EE   |             no               |
|     2 | DANE-TA   |             yes              |
|     3 | DANE-EE   |             yes              |

netdoc flags MX hosts with TLSA records of usage 0 or 1 as "deployed
but doesn't confer the PKIX-bypass benefit RFC 7672 intends" and
doesn't award credit. Only TLSA records with usage 2 or 3 on ≥1
MX earn the full 10 points.

### 7. IPv6-MX

For each MX hostname, we look up AAAA. ≥1 MX with an AAAA record →
full 10 points. Internet.nl includes this in its mail rating because
IPv6-only senders (increasingly common: mobile carriers, EU government
CDNs) cannot deliver mail to MX hosts without AAAA.

We additionally attempt a TCP-25 connect to the IPv6 address; failure
is reported as informational (egress firewalls commonly block 25/tcp)
and doesn't affect the score.

## Adjacent signals (not scored, surfaced separately)

- **BIMI**: BIMI record + VMC URL → surfaced in the hint
- **DMARC external-destination authorization** (RFC 7489 §7.1) →
  surfaced as a separate finding when violated
- **MX STARTTLS upgrade** → per-MX cert inspection; not scored to
  avoid penalizing networks where outbound port 25 is blocked
- **DKIM selector revocation** (empty `p=`) → flagged in the dkim_keys
  array but doesn't bring the score below 0

## Honest gaps (roadmap)

netdoc does NOT currently score:

- **ARC (RFC 8617)** — Authenticated Received Chain. ARC scores
  forwarded-mail traversal, which can only be verified by sending
  test mail through the domain; netdoc deliberately doesn't send mail
  to preserve the unprivileged-CLI brand. If you need ARC scoring,
  use [mecsa.jrc.ec.europa.eu](https://mecsa.jrc.ec.europa.eu) which
  sends real test mail and analyzes the bounce.
- **Full DANE-TA chain validation**. We confirm the TLSA record is
  present with usage 2/3 but don't currently verify the chain
  semantics per RFC 7671 (matching-type 0/1/2 vs cert binding).
- **RPKI full-RIB walk for MX networks**. We do per-prefix RPKI
  validation via Team Cymru DNS (in the DNS check), but a true
  full-RIB walk against the RIPE RPKI archive is out of scope.
- **DMARC psd= tag (RFC 9091)**. Public Suffix Domain marker;
  not yet parsed.

## How to read the JSON output

```
$ netdoc --check mail --json example.com | jq '.checks[]|select(.name=="Mail").detail'
{
  "score": 87,
  "grade": "B",
  "spf":    { "raw": "v=spf1 ...", "all": "-all", ... },
  "dmarc":  { "raw": "v=DMARC1; p=reject; ...", "policy": "reject", ... },
  "dkim":   [ { "name": "google", "found": true } ],
  "dkim_keys":    [ { "selector": "google", "algo": "rsa", "bits": 2048, "strong": true } ],
  "mtasts":       { "policy_present": true, "mode": "enforce", "max_age": 86400, "mx": ["..."] },
  "tlsrpt":       { "present": true, "rua": ["mailto:reports@..."] },
  "mx_starttls":  [ { "host": "...", "upgrade_succeeded": true, ... } ],
  "mx_dane":      [ { "mx_host": "...", "found": true, "has_dane_ee": true, "smtp_compliant": true } ],
  "mx_ipv6":      [ { "mx_host": "...", "has_aaaa": true, "address": "2001:db8::1", "reachable": true } ]
}
```

## References

- [internet.nl mail FAQ](https://internet.nl/faqs/report/)
- [Red Sift / Hardenize Email Infrastructure policy](https://www.hardenize.com)
- [RFC 7208 — Sender Policy Framework](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 7489 — DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 9091 — DMARC PSD](https://datatracker.ietf.org/doc/html/rfc9091)
- [RFC 6376 — DKIM Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 8461 — MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461)
- [RFC 8460 — SMTP TLS Reporting](https://datatracker.ietf.org/doc/html/rfc8460)
- [RFC 7672 — DANE for SMTP](https://datatracker.ietf.org/doc/html/rfc7672)
- [RFC 8617 — ARC (deferred)](https://datatracker.ietf.org/doc/html/rfc8617)
