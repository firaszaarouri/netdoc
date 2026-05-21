package main

import (
	"strconv"
	"strings"
)

// curl-style --write-out format template. The user passes a string like
//
//   netdoc github.com --write-out '${time_total}ms  ${grade}  ${tls_version}\n'
//
// and we substitute the ${varname} tokens with values pulled from the Report.
// Escapes \n, \r, \t are processed. Anything else stays literal.
//
// Variable namespace is FLAT — short scriptable identifiers that map to the
// fields a CI / monitoring script most often wants:
//
//   GLOBAL
//     ${target}           target as supplied
//     ${host}             resolved hostname
//     ${port}             port number
//     ${scheme}           http / https
//     ${healthy}          true / false
//     ${problems}         comma-separated list of problem summaries
//     ${fix_first}        the "fix first" recommendation
//     ${elapsed}          total wall time
//     ${exit_code}        0 / 1
//
//   TIMING (from trace)
//     ${time_dns}         DNS phase ms
//     ${time_tcp}         TCP phase ms
//     ${time_tls}         TLS phase ms
//     ${time_server}      Server phase ms
//     ${time_total}       Total wall ms
//     ${ttfb}             DNS+TCP+TLS+Server ms
//
//   HTTP
//     ${http_status}      e.g. 200
//     ${http_proto}       e.g. HTTP/2.0
//     ${http_server}      Server header
//     ${redirects}        redirect count
//     ${throughput_kbps}  body throughput
//
//   TLS
//     ${tls_version}      negotiated TLS version
//     ${cipher}           negotiated cipher name
//     ${days_left}        cert days until expiry
//     ${grade}            Security grade A+/A/B/...
//     ${score}            Security 0-100 score
//     ${vulns}            comma-separated CVE names found
//     ${jarm}             JARM fingerprint (62 chars)
//
//   DNS
//     ${ipv4}             first IPv4
//     ${ipv6}             first IPv6
//     ${asn}              first AS number
//     ${propagation}      consistent / split / partial / failed
//
//   MAIL
//     ${mail_score}       0-100
//     ${mail_grade}       letter
//     ${spf}              SPF terminal mechanism
//     ${dmarc}            DMARC policy
//
// Unknown variables expand to empty string. The substitution is left-to-right;
// nested ${} is not supported. Cost is O(format_length) — single pass.

// runWriteOut substitutes ${varname} tokens in the template using values
// from the report.
func runWriteOut(template string, r *Report, exitCode int) string {
	template = processEscapes(template)
	values := writeOutValues(r, exitCode)
	var out strings.Builder
	i := 0
	for i < len(template) {
		// Look for ${...}
		if i+1 < len(template) && template[i] == '$' && template[i+1] == '{' {
			end := strings.IndexByte(template[i+2:], '}')
			if end >= 0 {
				name := template[i+2 : i+2+end]
				out.WriteString(values[name])
				i += 2 + end + 1
				continue
			}
		}
		out.WriteByte(template[i])
		i++
	}
	return out.String()
}

// processEscapes handles \n, \r, \t, \\ escapes in a template.
func processEscapes(t string) string {
	var out strings.Builder
	out.Grow(len(t))
	for i := 0; i < len(t); i++ {
		if t[i] != '\\' || i+1 >= len(t) {
			out.WriteByte(t[i])
			continue
		}
		switch t[i+1] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case '\\':
			out.WriteByte('\\')
		default:
			out.WriteByte(t[i])
			out.WriteByte(t[i+1])
		}
		i++
	}
	return out.String()
}

// writeOutValues builds the variable map from the report.
func writeOutValues(r *Report, exitCode int) map[string]string {
	v := map[string]string{
		"target":    r.Target,
		"host":      r.Host,
		"port":      strconv.Itoa(r.Port),
		"scheme":    r.Scheme,
		"healthy":   strconv.FormatBool(r.Healthy),
		"problems":  strings.Join(r.Problems, ", "),
		"fix_first": r.FixFirst,
		"elapsed":   r.Elapsed,
		"exit_code": strconv.Itoa(exitCode),
	}
	if r.Trace != nil {
		v["time_dns"] = formatMS(r.Trace.DNSPhase)
		v["time_tcp"] = formatMS(r.Trace.TCPPhase)
		v["time_tls"] = formatMS(r.Trace.TLSPhase)
		v["time_server"] = formatMS(r.Trace.ServerPhase)
		v["time_total"] = formatMS(r.Trace.TotalPhase)
		v["ttfb"] = formatMS(r.Trace.TCPPhase + r.Trace.TLSPhase + r.Trace.ServerPhase + r.Trace.DNSPhase)
		v["http_status"] = strconv.Itoa(r.Trace.HTTPStatus)
		v["http_proto"] = r.Trace.HTTPProto
		v["http_server"] = r.Trace.HTTPServer
		v["redirects"] = strconv.Itoa(r.Trace.HTTPRedirects)
		v["throughput_kbps"] = formatMS(r.Trace.ThroughputKBps)
	}
	for _, c := range r.Checks {
		switch c.Name {
		case "TLS":
			if d := c.Detail; d != nil {
				v["tls_version"] = strOrEmpty(d["version"])
				v["cipher"] = strOrEmpty(d["cipher"])
				if dl, ok := d["days_left"].(int); ok {
					v["days_left"] = strconv.Itoa(dl)
				}
				if vulns, ok := d["vulnerabilities"].([]tlsVuln); ok {
					var names []string
					for _, vv := range vulns {
						names = append(names, vv.Name)
					}
					v["vulns"] = strings.Join(names, ",")
				}
				if j, ok := d["jarm"].(jarmResult); ok {
					v["jarm"] = j.Fingerprint
				}
			}
		case "Security":
			if d := c.Detail; d != nil {
				if s, ok := d["score"].(int); ok {
					v["score"] = strconv.Itoa(s)
				}
				v["grade"] = strOrEmpty(d["grade"])
			}
		case "DNS":
			if d := c.Detail; d != nil {
				if ips, ok := d["ipv4"].([]string); ok && len(ips) > 0 {
					v["ipv4"] = ips[0]
				}
				if ips, ok := d["ipv6"].([]string); ok && len(ips) > 0 {
					v["ipv6"] = ips[0]
				}
				if asn, ok := d["asn"].(map[string]asnInfo); ok {
					for _, info := range asn {
						v["asn"] = info.ASN
						break
					}
				}
				if prop, ok := d["propagation"].(propagationVerdict); ok {
					v["propagation"] = prop.Verdict
				}
			}
		case "Mail":
			if d := c.Detail; d != nil {
				if s, ok := d["score"].(int); ok {
					v["mail_score"] = strconv.Itoa(s)
				}
				v["mail_grade"] = strOrEmpty(d["grade"])
				if spf, ok := d["spf"].(*spfPolicy); ok && spf != nil {
					v["spf"] = spf.All
				}
				if dm, ok := d["dmarc"].(*dmarcPolicy); ok && dm != nil {
					v["dmarc"] = dm.Policy
				}
			}
		}
	}
	return v
}

// formatMS formats a float milliseconds value to 1 decimal place.
func formatMS(v float64) string {
	if v == 0 {
		return "0"
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// strOrEmpty returns the string value or "" if not a string.
func strOrEmpty(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
