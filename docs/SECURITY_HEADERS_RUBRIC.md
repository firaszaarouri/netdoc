# netdoc — security-headers scoring rubric

netdoc grades HTTP response headers against the modern industry baseline
defined by securityheaders.com, Mozilla Observatory, the OWASP Secure
Headers Project, and Google CSP Evaluator. The rubric below is the
exact algorithm `checkSecurityHeaders()` runs in
[security_headers.go](../security_headers.go) and `evaluateCSP()` runs
in [csp_parser.go](../csp_parser.go).

## Overall score (0 – 100)

The header weights below sum to exactly 100. A perfect deployment with
every header set to a strict value scores 100. A deployment with no
hardening headers at all scores 0.

| Weight | Header                          | Pass criterion                                                                                          |
| ------:| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
|     20 | `Strict-Transport-Security`     | `max-age` ≥ 6 months (soft) / ≥ 1 year + `includeSubDomains` + `preload` (full preload-eligible)        |
|     20 | `Content-Security-Policy`       | Strictness ≥ `moderate` per the CSP Level 3 rubric below                                                |
|     12 | `X-Frame-Options`               | `DENY` or `SAMEORIGIN` (or `frame-ancestors` set on the CSP)                                            |
|     10 | `X-Content-Type-Options`        | `nosniff`                                                                                               |
|      8 | `Referrer-Policy`               | Any explicit value (policy choice is application-dependent)                                             |
|      8 | `Cross-Origin-Opener-Policy`    | Present (defaults are meaningful — `same-origin`, `same-origin-allow-popups`, `unsafe-none`)            |
|      5 | `Permissions-Policy`            | Present                                                                                                  |
|      4 | `Cross-Origin-Embedder-Policy`  | Present (typical: `require-corp` or `credentialless`)                                                   |
|      4 | `Cross-Origin-Resource-Policy`  | Present (typical: `same-origin` / `same-site` / `cross-origin`)                                         |
|      3 | `Origin-Agent-Cluster`          | `?1` (opts the origin into a dedicated agent cluster for Spectre isolation)                             |
|      3 | `Document-Policy`               | Present (modern feature-policy successor)                                                               |
|      3 | `Reporting-Endpoints`           | Present (`report-to` Reporting API endpoint group)                                                      |
| **100** | **Total**                       |                                                                                                          |

### Letter grades

| Score   | Grade |
| ------: | :---: |
| 90 –100 | **A** |
| 80 – 89 | **B** |
| 70 – 79 | **C** |
| 60 – 69 | **D** |
| < 60    | **F** |

The check returns `StatusOK` when score ≥ 80, `StatusWarn` otherwise.
There is no `StatusFail` for headers — a missing header isn't a
runtime failure, just a missed hardening opportunity.

## CSP Level 3 strictness rubric

The Content-Security-Policy header is the strongest defensive signal a
site can ship, so netdoc grades it deeply rather than just on presence.
The CSP grader returns a strictness label (`strict` / `moderate` /
`loose` / `missing`) and a 0 – 100 strictness score, with the headline
surfaced in the Security check's hint.

A policy starts at 100 points; netdoc subtracts per finding.

### Critical findings (-20 each)

| Finding                                                                                  | Severity | Why                                                                                                                                 |
| ---------------------------------------------------------------------------------------- |:--------:| ------------------------------------------------------------------------------------------------------------------------------------ |
| `'unsafe-inline'` in `script-src` with no nonce, hash, or `'strict-dynamic'` escape hatch | critical | Allows arbitrary inline `<script>` and event handlers — the canonical XSS surface                                                   |
| `'unsafe-eval'` in `script-src`                                                          | critical | Permits `eval()` / `new Function(...)` — bypasses every other allowlist                                                              |
| Bare wildcard `*` or schema source (`data:`, `blob:`, `http:`, `https:`, `filesystem:`, `ws:`, `wss:`) in `script-src` | critical | Allows scripts from any origin or arbitrary protocol — defeats the directive                                                         |
| `object-src` not `'none'`                                                                | critical | Legacy plugin XSS surface (Flash, Java applets) — modern apps don't need any object source                                          |

### High findings (-15 each)

| Finding                                       | Severity | Why                                                                              |
| --------------------------------------------- |:--------:| -------------------------------------------------------------------------------- |
| `default-src` absent                          |  high    | Non-script directives default to wide-open without an explicit fallback          |
| `script-src` absent (no `default-src` either) |  high    | No scripting policy in effect                                                    |
| `base-uri` unset                              |  high    | Attacker can inject `<base href>` and bypass relative-URL allowlists             |
| `form-action` unset                           |  high    | Forms can exfiltrate credentials to attacker-controlled destinations             |

### Medium findings (-10 each)

| Finding                                                       | Severity | Why                                                                                       |
| ------------------------------------------------------------- |:--------:| ----------------------------------------------------------------------------------------- |
| `frame-ancestors` unset                                       | medium   | Clickjacking via iframe — XFO covers the same surface but is legacy                       |
| `'unsafe-hashes'` present                                     | medium   | Allows inline event-handler scripts (`onclick="..."` etc.) via hash                       |
| No reporting endpoint (`report-to` or `report-uri`)           | medium   | No violation telemetry — silent policy degradation                                        |
| Nonces in use without `'strict-dynamic'`                      | medium   | Host allowlist is still enforced; modern best practice is `'strict-dynamic'` to drop it   |

### Low findings (-5 each)

| Finding                                  | Severity | Why                                                          |
| ---------------------------------------- |:--------:| ------------------------------------------------------------ |
| `upgrade-insecure-requests` not set      |   low    | Mixed-content subresources won't auto-upgrade to HTTPS       |

### Bonuses (cap at 100)

| Bonus                                  | Points |
| -------------------------------------- | -----: |
| Nonces in use anywhere                 |     +5 |
| Hashes in use anywhere                 |     +5 |
| `'strict-dynamic'` in use              |    +10 |

### Strictness labels

| Score     | Label      | Meaning                                                                  |
| --------: | :--------- | ------------------------------------------------------------------------ |
|   90 –100 | `strict`   | Modern hardened policy — pass                                            |
|   60 – 89 | `moderate` | Pass-grade with at least one named weakness                              |
|    < 60   | `loose`    | Fail — the CSP grader returns Pass=false                                 |
| no policy | `missing`  | No `Content-Security-Policy` header                                      |

## Other audits surfaced

Beyond the per-header pass/fail grading, the Security check additionally surfaces:

- **Cookie audit** — every `Set-Cookie` header is inspected for `Secure`, `HttpOnly`, `SameSite`, and the `__Host-` / `__Secure-` prefix conventions
- **Deprecated headers** — flags `Public-Key-Pins`, `Public-Key-Pins-Report-Only`, `Expect-CT`, `X-XSS-Protection`, `Pragma` if present
- **Information-leak headers** — flags `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache` if present
- **OWASP Secure Headers Project compliance** — binary pass/fail per rule against the published OWASP baseline
- **CORS misconfig probe** — separate check that lives in the HTTP check, but the verdict feeds back into the Security narrative

## How to read the JSON output

```
$ netdoc --check security --json https://example.com | jq '.checks[]|select(.name=="Security").detail'
{
  "score": 87,
  "grade": "B",
  "headers": [ { "name": "Strict-Transport-Security", "short": "HSTS",
                 "present": true, "pass": true, "weight": 20, "value": "..." }, ... ],
  "cookies": [ ... ],
  "deprecated_headers": [ ... ],
  "info_leak_headers": [ ... ],
  "owasp": { ... },
  "csp_analysis": {
    "strictness": "moderate",
    "score": 80,
    "findings": [ { "directive": "form-action", "severity": "high",
                    "issue": "form-action unset — credential exfil ...",
                    "suggestion": "set form-action 'self'" } ],
    "uses_nonces": true,
    "strict_dynamic": true,
    "reporting_on": true
  }
}
```

The `csp_analysis` block uses the same model Google CSP Evaluator does, but as data not a hosted UI — pipe it through `jq`, alert on `findings[].severity == "critical"` in CI, baseline with `--diff`.

## References

- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) — the algorithmic basis for our CSP scoring
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) — W3C Working Draft
- [WHATWG: Origin-Agent-Cluster](https://html.spec.whatwg.org/multipage/origin.html#origin-keyed-agent-clusters)
- [Document Policy explainer](https://github.com/WICG/document-policy)
- [Reporting API spec](https://w3c.github.io/reporting/)
