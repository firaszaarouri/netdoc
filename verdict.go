package main

import "time"

// buildReport aggregates the individual checks into a single verdict.
func buildReport(d *diagnosis, checks []Check, trace *TraceResult, elapsed time.Duration) Report {
	r := Report{
		Target:  d.scheme + "://" + d.host,
		Host:    d.host,
		Port:    d.port,
		Scheme:  d.scheme,
		Checks:  checks,
		Trace:   trace,
		Elapsed: dur(elapsed),
	}

	for _, c := range checks {
		if c.Status == StatusFail || c.Status == StatusWarn {
			r.Problems = append(r.Problems, c.Name+" — "+c.Summary)
		}
	}

	// "Fix first" points at the first failure, or the first warning if nothing failed.
	for _, c := range checks {
		if c.Status == StatusFail {
			r.FixFirst = c.Name + ": " + c.Summary
			break
		}
	}
	if r.FixFirst == "" {
		for _, c := range checks {
			if c.Status == StatusWarn {
				r.FixFirst = c.Name + ": " + c.Summary
				break
			}
		}
	}

	r.Healthy = len(r.Problems) == 0
	return r
}
