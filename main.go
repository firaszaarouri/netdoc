package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var useColor = true

func main() {
	enableANSI()

	args := os.Args[1:]
	var target string
	var batchTargets []string
	jsonOut := false
	timeout := 5 * time.Second
	var transportSpec string
	var portsSpec string
	var ecsSpec string
	var writeOutTemplate string
	var diffBaseline string
	var checkSpec string
	var profileSpec string
	var starttlsSpec string
	var cipherPattern string
	var historyTarget string
	historyN := 10
	var batchFile string
	batchConcurrency := 8
	noHistory := false
	var reportFormat string
	var outputFile string
	dnssecTreeFlag := false
	eachCipherFlag := false

	watchMode := false
	watchInterval := 5 * time.Second

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--no-color":
			useColor = false
		case a == "--watch":
			watchMode = true
		case strings.HasPrefix(a, "--watch="):
			watchMode = true
			if d, err := time.ParseDuration(strings.TrimPrefix(a, "--watch=")); err == nil {
				watchInterval = d
			}
		case a == "--interval":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil {
					watchInterval = d
				}
			}
		case strings.HasPrefix(a, "--interval="):
			if d, err := time.ParseDuration(strings.TrimPrefix(a, "--interval=")); err == nil {
				watchInterval = d
			}
		case a == "-h" || a == "--help":
			printUsage()
			return
		case a == "--help-flags":
			// One-flag-per-line compact form for shell-completion authors,
			// grep, awk pipelines, and quick discovery.
			printFlagList()
			return
		case a == "-v" || a == "--version":
			fmt.Println("netdoc " + version)
			return
		case a == "--timeout":
			if i+1 < len(args) {
				i++
				if t, err := time.ParseDuration(args[i]); err == nil {
					timeout = t
				}
			}
		case strings.HasPrefix(a, "--timeout="):
			if t, err := time.ParseDuration(strings.TrimPrefix(a, "--timeout=")); err == nil {
				timeout = t
			}
		case a == "--dns":
			if i+1 < len(args) {
				i++
				transportSpec = args[i]
			}
		case strings.HasPrefix(a, "--dns="):
			transportSpec = strings.TrimPrefix(a, "--dns=")
		case a == "--ports":
			if i+1 < len(args) {
				i++
				portsSpec = args[i]
			}
		case strings.HasPrefix(a, "--ports="):
			portsSpec = strings.TrimPrefix(a, "--ports=")
		case a == "--ecs":
			// `--ecs` alone uses the geographically-diverse default bouquet.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				ecsSpec = args[i]
			} else {
				ecsSpec = "default"
			}
		case strings.HasPrefix(a, "--ecs="):
			ecsSpec = strings.TrimPrefix(a, "--ecs=")
		case a == "--write-out":
			if i+1 < len(args) {
				i++
				writeOutTemplate = args[i]
			}
		case strings.HasPrefix(a, "--write-out="):
			writeOutTemplate = strings.TrimPrefix(a, "--write-out=")
		case a == "--diff":
			if i+1 < len(args) {
				i++
				diffBaseline = args[i]
			}
		case strings.HasPrefix(a, "--diff="):
			diffBaseline = strings.TrimPrefix(a, "--diff=")
		case a == "--check":
			if i+1 < len(args) {
				i++
				checkSpec = args[i]
			}
		case strings.HasPrefix(a, "--check="):
			checkSpec = strings.TrimPrefix(a, "--check=")
		case a == "--profile":
			if i+1 < len(args) {
				i++
				profileSpec = args[i]
			}
		case strings.HasPrefix(a, "--profile="):
			profileSpec = strings.TrimPrefix(a, "--profile=")
		case a == "--starttls", a == "-t":
			// Mirror testssl.sh's `-t / --starttls <protocol>` flag.
			if i+1 < len(args) {
				i++
				starttlsSpec = args[i]
			}
		case strings.HasPrefix(a, "--starttls="):
			starttlsSpec = strings.TrimPrefix(a, "--starttls=")
		case a == "--cipher-pattern", a == "-x":
			// Mirror testssl.sh's `-x <pattern>` flag.
			if i+1 < len(args) {
				i++
				cipherPattern = args[i]
			}
		case strings.HasPrefix(a, "--cipher-pattern="):
			cipherPattern = strings.TrimPrefix(a, "--cipher-pattern=")
		case a == "-f", a == "--file":
			if i+1 < len(args) {
				i++
				batchFile = args[i]
			}
		case strings.HasPrefix(a, "--file="):
			batchFile = strings.TrimPrefix(a, "--file=")
		case a == "--concurrency":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					batchConcurrency = n
				}
			}
		case strings.HasPrefix(a, "--concurrency="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--concurrency=")); err == nil && n > 0 {
				batchConcurrency = n
			}
		case a == "--no-history":
			noHistory = true
		case a == "--history":
			// `--history` with no integer means default count; with an int
			// means "last N records".
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					historyN = n
					i++
				}
			}
			historyTarget = "__pending__" // resolved to the positional target after the loop
		case strings.HasPrefix(a, "--history="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--history=")); err == nil && n > 0 {
				historyN = n
			}
			historyTarget = "__pending__"
		case a == "--format":
			if i+1 < len(args) {
				i++
				reportFormat = args[i]
			}
		case strings.HasPrefix(a, "--format="):
			reportFormat = strings.TrimPrefix(a, "--format=")
		case a == "--output" || a == "-o":
			// Write report output to a file directly (via Go file I/O),
			// bypassing the shell pipeline. This avoids the UTF-8 mangling
			// that PowerShell's `|` / `>` inflict on non-ASCII glyphs.
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			}
		case strings.HasPrefix(a, "--output="):
			outputFile = strings.TrimPrefix(a, "--output=")
		case a == "--dnssec-tree":
			// ASCII chain visualizer in the DNS check's hint. Lock-in vs DNSViz.
			dnssecTreeFlag = true
		case a == "--each-cipher":
			// testssl --each-cipher: probe every codepoint in the IANA cipher
			// registry at TLS 1.0/1.1/1.2 using the elimination algorithm.
			eachCipherFlag = true
		default:
			if !strings.HasPrefix(a, "-") && target == "" {
				target = a
			} else if !strings.HasPrefix(a, "-") {
				// Additional positional args become batch targets.
				batchTargets = append(batchTargets, a)
			}
		}
	}

	if jsonOut || os.Getenv("NO_COLOR") != "" {
		useColor = false
	}

	// Resolve --history target: --history can come before or after the
	// positional target argument. If we saw --history without a target,
	// promote the positional to the history selector now.
	if historyTarget == "__pending__" {
		historyTarget = target
	}
	if historyTarget != "" {
		recs, err := readHistory(historyTarget, historyN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: --history: "+err.Error())
			os.Exit(2)
		}
		renderHistoryTable(os.Stdout, historyTarget, recs)
		return
	}

	// Build the configure closure once — applied per-target both in
	// single-target mode and batch mode.
	var globalFilter *checkFilter
	if profileSpec != "" {
		pf, err := parseProfile(profileSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: "+err.Error())
			os.Exit(2)
		}
		globalFilter = pf
	}
	if checkSpec != "" {
		cf, err := parseCheckFilter(checkSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: "+err.Error())
			os.Exit(2)
		}
		// --check overrides --profile when both are set (more specific wins).
		globalFilter = cf
	}
	// Resolve --starttls before configuring per-target diagnosis so the
	// default port lookup is shared.
	var starttlsProto startTLSProtocol
	if starttlsSpec != "" {
		p, err := parseSTARTTLSProtocol(starttlsSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: "+err.Error())
			os.Exit(2)
		}
		starttlsProto = p
	}

	configureDiagnosis := func(d *diagnosis) {
		d.timeout = timeout
		d.filter = globalFilter
		d.cipherPattern = cipherPattern
		d.dnssecTree = dnssecTreeFlag
		d.eachCipher = eachCipherFlag
		if starttlsProto != "" {
			d.starttlsProto = starttlsProto
			// Default the port to the protocol's canonical when not
			// explicitly set by the URL — this matches testssl.sh's
			// behavior where `-t imap example.com` auto-targets 143.
			if d.port == 0 || d.port == 443 || d.port == 80 {
				d.port = defaultPortForSTARTTLS(starttlsProto)
			}
			// For STARTTLS, the scheme is implicit (not http/https) so
			// downstream checks that gate on https can be skipped or
			// adapted via the filter; here we keep scheme as-is so
			// JSON consumers still see what was requested.
		}
		if transportSpec != "" {
			tr, err := parseDNSTransport(transportSpec)
			if err == nil {
				d.dnsTransport = tr
			}
		}
		if portsSpec != "" {
			if ports, err := parsePortSpec(portsSpec); err == nil {
				d.portsToScan = ports
			}
		}
		if ecsSpec != "" {
			if ecsSpec == "default" {
				d.ecsSubnets = append([]string(nil), defaultECSSubnets...)
			} else {
				for _, s := range strings.Split(ecsSpec, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						d.ecsSubnets = append(d.ecsSubnets, s)
					}
				}
			}
		}
	}

	// Batch mode: triggered by -f / --file OR by multiple positional args.
	if batchFile != "" || len(batchTargets) > 0 {
		var allTargets []string
		if batchFile != "" {
			ts, err := readTargetsFile(batchFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "netdoc: -f: "+err.Error())
				os.Exit(2)
			}
			allTargets = append(allTargets, ts...)
		}
		if target != "" {
			allTargets = append(allTargets, target)
		}
		allTargets = append(allTargets, batchTargets...)
		if len(allTargets) == 0 {
			fmt.Fprintln(os.Stderr, "netdoc: no targets supplied")
			os.Exit(2)
		}
		unhealthy := runBatch(batchConfig{
			targets:     allTargets,
			concurrency: batchConcurrency,
			jsonOut:     jsonOut,
			noHistory:   noHistory,
			configure:   configureDiagnosis,
		})
		if unhealthy > 0 {
			os.Exit(1)
		}
		return
	}

	if target == "" {
		printUsage()
		os.Exit(2)
	}

	host, port, scheme, err := parseTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netdoc: "+err.Error())
		os.Exit(2)
	}

	d := &diagnosis{host: host, port: port, scheme: scheme, timeout: timeout}
	configureDiagnosis(d)

	if watchMode {
		if jsonOut {
			fmt.Fprintln(os.Stderr, "netdoc: --watch and --json are mutually exclusive")
			os.Exit(2)
		}
		runWatch(d, watchInterval)
		return
	}

	report := runAllChecks(d)

	exitCode := 0
	if !report.Healthy {
		exitCode = 1
	}

	if !noHistory {
		_ = appendHistory(report)
	}

	// --output with a recognised extension implies the format, so
	// `netdoc host --output report.html` works without a separate --format.
	if outputFile != "" && reportFormat == "" && !jsonOut {
		switch {
		case strings.HasSuffix(outputFile, ".html"), strings.HasSuffix(outputFile, ".htm"):
			reportFormat = "html"
		case strings.HasSuffix(outputFile, ".md"), strings.HasSuffix(outputFile, ".markdown"):
			reportFormat = "md"
		case strings.HasSuffix(outputFile, ".json"):
			jsonOut = true
		}
	}

	switch {
	case diffBaseline != "":
		baseline, err := loadBaseline(diffBaseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: --diff failed to load baseline: "+err.Error())
			os.Exit(2)
		}
		diffs := reportDiff(baseline, &report)
		fmt.Print(renderDiff(diffs, diffBaseline))
		if len(diffs) > 0 && exitCode == 0 {
			exitCode = 1 // any drift is a CI gate signal
		}
	case writeOutTemplate != "":
		// --write-out suppresses normal output entirely; only the template
		// goes to stdout. The exit code still reflects health.
		fmt.Print(runWriteOut(writeOutTemplate, &report, exitCode))
	case reportFormat == "html":
		emitReport(renderHTML(report), outputFile)
	case reportFormat == "md" || reportFormat == "markdown":
		emitReport(renderMarkdown(report), outputFile)
	case jsonOut:
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "netdoc: "+err.Error())
			os.Exit(2)
		}
		emitReport(string(b)+"\n", outputFile)
	default:
		renderTerminal(report)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// runAllChecks executes every diagnostic in the canonical order and returns
// the assembled report. Pulled out so --watch mode can drive the same pipeline
// on each tick. d.filter (populated by --check or --profile) narrows the
// check set — nil filter means run everything (default behavior preserved).
func runAllChecks(d *diagnosis) Report {
	start := time.Now()
	// runStage runs the check func only when the filter permits its name.
	runStage := func(name string, fn func() Check) (Check, bool) {
		if !d.filter.permits(name) {
			return Check{}, false
		}
		return fn(), true
	}

	var checks []Check
	add := func(c Check, ok bool) {
		if ok {
			checks = append(checks, c)
		}
	}

	add(runStage("DNS", d.checkDNS))
	add(runStage("Domain", d.checkDomain))
	add(runStage("Delegation", d.checkDelegation))
	add(runStage("TCP", d.checkTCP))
	add(runStage("Latency", d.checkLatency))
	add(runStage("Path", d.checkPath))

	// runTrace populates d.trace, which the HTTP check, timing chart,
	// AND the TLS grade (HSTS detection for A+ uplift) all read.
	if d.filter.permits("HTTP") || d.filter.permits("Security") || d.filter.permits("Discovery") || d.filter.permits("TLS") {
		d.runTrace()
	}

	add(runStage("TLS", d.checkTLS))
	add(runStage("HTTP", d.checkHTTP))
	add(runStage("Security", d.checkSecurityHeaders))
	add(runStage("Discovery", d.checkDiscovery))
	add(runStage("Mail", d.checkMail))
	add(runStage("Reputation", d.checkReputation))
	add(runStage("IPv6", d.checkIPv6))

	if len(d.portsToScan) > 0 && d.filter.permits("Ports") {
		checks = append(checks, d.checkPorts())
	}
	elapsed := time.Since(start)
	return buildReport(d, checks, d.trace, elapsed)
}

// parseTarget extracts host, port and scheme from a hostname or URL argument.
func parseTarget(arg string) (host string, port int, scheme string, err error) {
	scheme = "https"
	if strings.Contains(arg, "://") {
		u, e := url.Parse(arg)
		if e != nil {
			return "", 0, "", e
		}
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
	} else {
		host = arg
		if h, p, e := net.SplitHostPort(arg); e == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}

	if host == "" {
		return "", 0, "", fmt.Errorf("could not find a hostname in %q", arg)
	}
	if scheme != "http" && scheme != "https" {
		return "", 0, "", fmt.Errorf("unsupported scheme %q (use http or https)", scheme)
	}
	if port == 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	return host, port, scheme, nil
}

// emitReport writes formatted output to the --output file when set,
// otherwise to stdout. Writing the file directly with os.WriteFile is the
// reliable way to preserve UTF-8 on Windows: piping a native command
// through PowerShell's `|` or `>` re-encodes the bytes via the console
// code page (CP1252/CP850), mangling the · / — / ✓ glyphs. Go's file I/O
// bypasses the shell entirely.
func emitReport(content, outputFile string) {
	if outputFile == "" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(outputFile, []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "netdoc: --output: "+err.Error())
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "netdoc: wrote "+outputFile)
}

func printUsage() {
	fmt.Println()
	renderBanner(helpInfo())
	fmt.Println()
	fmt.Println(`USAGE:
  netdoc <host-or-url> [flags]

EXAMPLES:
  netdoc example.com
  netdoc https://api.example.com
  netdoc example.com:8443
  netdoc example.com --json

FLAGS:
  --json            output a structured JSON report
  --format <fmt>    output format: json | html | md / markdown
  -o, --output <f>  write the report to a file instead of stdout. Format is
                    inferred from the extension (.html/.md/.json) if --format
                    isn't given. Avoids the UTF-8 mangling that shell pipes
                    cause on Windows PowerShell.
  --timeout <dur>   per-check timeout (default 5s), e.g. --timeout 10s
  --dns <spec>      DNS transport: system (default), udp, tcp, dot, doh, doq.
                    Optionally followed by ":server", e.g. dot:1.1.1.1,
                    doh:https://cloudflare-dns.com/dns-query, doq:1.1.1.1
  --ports <spec>    scan the given ports, e.g. 22,80,443 or 1-1024 or
                    one of the presets top20 / top100 / top1000 (nmap's
                    most-common lists). Open ports are banner-grabbed
                    (SSH/SMTP/...) or actively probed (10 protocols
                    including SSH/LDAP/PG/Redis/ES/Memcached/Mongo/NTP/DNS).
  --ecs [<cidr>]    EDNS Client-Subnet probe — query an authoritative
                    server while spoofing the client subnet to see
                    GeoDNS/CDN steering. Pass a CIDR (or comma-list of
                    CIDRs), or no argument for the default 5-continent
                    bouquet (US/DE/JP/BR/AU).
  --check <list>    run only the named checks (comma-separated). Valid:
                    dns, domain, delegation, tcp, latency, path, tls,
                    http, security, discovery, mail, reputation, ipv6,
                    ports. Example: --check tls,dns,http
  --profile <name>  use a curated check preset: fast / web / mail / full /
                    paranoid. --check overrides --profile when both set.
  -t, --starttls <protocol>
                    upgrade a plaintext connection via STARTTLS before
                    running the TLS check. Mirrors testssl.sh's -t flag.
                    Valid: smtp / lmtp / pop3 / imap / ftp / nntp /
                    xmpp / xmpp-server / sieve / telnet / ldap / irc /
                    mysql / postgres. The default port for the protocol
                    is auto-selected (smtp=25, imap=143, ldap=389, ...)
                    unless overridden in the target URL.
  --diff <file>     compare current scan to a baseline JSON report
  --write-out <fmt> curl-style scriptable output template
  --watch [=dur]    live mode: re-run every check on an interval, redraw
                    in-place, show per-metric sparklines. Default interval
                    5s; override with --interval 2s or --watch=10s. Ctrl+C
                    exits cleanly.
  --interval <dur>  set the --watch interval explicitly
  --dnssec-tree     render the DNSSEC validation chain as an ASCII tree
                    (root → TLD → registrable-domain) in the DNS check's
                    hint. DNSViz-class chain visualisation in pure CLI.
  --each-cipher     enumerate every cipher the server accepts across
                    TLS 1.0/1.1/1.2 using the testssl.sh-style elimination
                    algorithm. Probes ~190 IANA cipher codepoints (modern
                    AEAD, ECDHE/DHE/RSA, RC4/3DES/DES/EXPORT/NULL legacy,
                    GOST/Camellia/SEED/ARIA/IDEA obscure, PSK/SRP/KRB5
                    niche). Slow (~5-20s) — opt-in.

BATCH MODE (multi-target):
  -f, --file <path> read newline-delimited targets from path (or "-" for
                    stdin). Blank lines and # comments are ignored.
  --concurrency N   batch parallelism (default 8)
  netdoc a.com b.com c.com    additional positional args become batch targets

HISTORY:
  --history [N]     show last N scans (default 10) for the given target
                    from ~/.netdoc/history.jsonl. Format-agnostic.
  --no-history      skip appending this scan to ~/.netdoc/history.jsonl

  --no-color        disable colored output
  -v, --version     show version
  -h, --help        show this help
  --help-flags      one-flag-per-line compact list (grep / completion-friendly)`)
}

// printFlagList writes every flag, one per line, to stdout. Designed for
// `netdoc --help-flags | grep --` patterns and shell-completion builders.
// Output is stable / sorted so diffs are minimal when flags change.
func printFlagList() {
	flags := []string{
		"--check",
		"--concurrency",
		"--diff",
		"--dns",
		"--dnssec-tree",
		"--each-cipher",
		"--ecs",
		"--file",
		"--format",
		"--help",
		"--help-flags",
		"--history",
		"--interval",
		"--json",
		"--no-color",
		"--no-history",
		"--output",
		"--ports",
		"--profile",
		"--starttls",
		"--timeout",
		"--version",
		"--watch",
		"--write-out",
		"-f",
		"-h",
		"-o",
		"-t",
		"-v",
	}
	for _, f := range flags {
		fmt.Println(f)
	}
}
