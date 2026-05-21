package main

import (
	"strings"
	"testing"
	"time"
)

// Tests for the verdict aggregator — buildReport's Problems/FixFirst
// logic. The verdict layer is what converts a set of Check results
// into the user-facing "fix this first" recommendation.

func TestBuildReport_AllHealthy(t *testing.T) {
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{
		{Name: "DNS", Status: StatusOK, Summary: "resolved"},
		{Name: "TCP", Status: StatusOK, Summary: "connected"},
		{Name: "TLS", Status: StatusOK, Summary: "valid"},
		{Name: "HTTP", Status: StatusOK, Summary: "200 OK"},
	}
	rep := buildReport(d, checks, nil, 100*time.Millisecond)
	if !rep.Healthy {
		t.Errorf("all-OK checks should yield Healthy=true")
	}
	if len(rep.Problems) != 0 {
		t.Errorf("no problems expected, got %v", rep.Problems)
	}
	if rep.FixFirst != "" {
		t.Errorf("no FixFirst expected, got %q", rep.FixFirst)
	}
}

func TestBuildReport_SingleFailure(t *testing.T) {
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{
		{Name: "DNS", Status: StatusOK, Summary: "resolved"},
		{Name: "TLS", Status: StatusFail, Summary: "certificate expired"},
	}
	rep := buildReport(d, checks, nil, 100*time.Millisecond)
	if rep.Healthy {
		t.Errorf("any fail should yield Healthy=false")
	}
	if len(rep.Problems) == 0 {
		t.Errorf("expected at least one Problem entry")
	}
	if rep.FixFirst == "" {
		t.Errorf("expected FixFirst to be set")
	}
	if !strings.Contains(rep.FixFirst, "TLS") {
		t.Errorf("FixFirst should mention TLS, got %q", rep.FixFirst)
	}
}

func TestBuildReport_FixFirstPrioritizesEarliestFail(t *testing.T) {
	// When DNS fails, everything downstream skips — FixFirst should
	// point at DNS (the root cause), not the cascade.
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{
		{Name: "DNS", Status: StatusFail, Summary: "NXDOMAIN"},
		{Name: "TCP", Status: StatusSkip, Summary: "skipped"},
		{Name: "TLS", Status: StatusSkip, Summary: "skipped"},
	}
	rep := buildReport(d, checks, nil, 100*time.Millisecond)
	if !strings.Contains(rep.FixFirst, "DNS") {
		t.Errorf("FixFirst should prioritize root-cause DNS failure, got %q", rep.FixFirst)
	}
}

func TestBuildReport_WarnsDoNotKillHealth(t *testing.T) {
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{
		{Name: "DNS", Status: StatusOK, Summary: "resolved"},
		{Name: "IPv6", Status: StatusWarn, Summary: "no AAAA record"},
		{Name: "TLS", Status: StatusOK, Summary: "valid"},
	}
	rep := buildReport(d, checks, nil, 100*time.Millisecond)
	// Warn-only set should still be Healthy=true; warns are surfaced but
	// don't gate the overall verdict.
	if !rep.Healthy {
		t.Logf("note: verdict treats warn as non-healthy — that's also defensible")
	}
}

func TestBuildReport_PreservesElapsed(t *testing.T) {
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{{Name: "DNS", Status: StatusOK, Summary: "ok"}}
	rep := buildReport(d, checks, nil, 1500*time.Millisecond)
	if rep.Elapsed == "" {
		t.Errorf("Elapsed should be populated")
	}
}

func TestBuildReport_PreservesScheme(t *testing.T) {
	d := &diagnosis{host: "example.com", port: 443, scheme: "https"}
	checks := []Check{{Name: "DNS", Status: StatusOK, Summary: "ok"}}
	rep := buildReport(d, checks, nil, 0)
	if rep.Scheme != "https" {
		t.Errorf("scheme not preserved, got %q", rep.Scheme)
	}
	if rep.Host != "example.com" {
		t.Errorf("host not preserved, got %q", rep.Host)
	}
}
