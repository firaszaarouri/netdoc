package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the multi-target batch + JSONL history machinery.

func TestReadTargetsFile_BasicLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.txt")
	contents := "github.com\ncloudflare.com\nexample.com\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	got, err := readTargetsFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := []string{"github.com", "cloudflare.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d]: got %q want %q", i, got[i], w)
		}
	}
}

func TestReadTargetsFile_CommentsAndBlanks(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.txt")
	contents := `# comment line
github.com

# another comment
   cloudflare.com
# trailing
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	got, err := readTargetsFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len: got %d want 2 — comments/blanks should be filtered, got %v", len(got), got)
	}
	if got[0] != "github.com" || got[1] != "cloudflare.com" {
		t.Errorf("got %v want [github.com, cloudflare.com]", got)
	}
}

func TestReadTargetsFile_NotFound(t *testing.T) {
	_, err := readTargetsFile("/nonexistent/path/that/should/not/exist.txt")
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestAppendAndReadHistory(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "history.jsonl")
	t.Setenv("NETDOC_HISTORY", path)

	rep1 := Report{Target: "https://github.com", Host: "github.com", Healthy: true, Elapsed: "100ms"}
	rep2 := Report{Target: "https://github.com", Host: "github.com", Healthy: false, FixFirst: "TLS issue", Elapsed: "200ms"}
	rep3 := Report{Target: "https://example.com", Host: "example.com", Healthy: true, Elapsed: "150ms"}

	for _, r := range []Report{rep1, rep2, rep3} {
		if err := appendHistory(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Filter by github.com host — should get rep1 + rep2.
	recs, err := readHistory("github.com", 100)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("history filter: got %d want 2", len(recs))
	}
	if !recs[0].Healthy {
		t.Errorf("first record should be healthy")
	}
	if recs[1].Healthy {
		t.Errorf("second record should be unhealthy")
	}
	if recs[1].FixFirst != "TLS issue" {
		t.Errorf("second record FixFirst: got %q want %q", recs[1].FixFirst, "TLS issue")
	}

	// No filter — should return all three.
	recs, err = readHistory("", 100)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("history all: got %d want 3", len(recs))
	}
}

func TestReadHistory_LimitN(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "history.jsonl")
	t.Setenv("NETDOC_HISTORY", path)

	// Append 5 records.
	for i := 0; i < 5; i++ {
		_ = appendHistory(Report{Host: "x.com", Healthy: true})
	}

	// Limit to 3 should return last 3.
	recs, err := readHistory("x.com", 3)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("limit: got %d want 3", len(recs))
	}
}

func TestReadHistory_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("NETDOC_HISTORY", filepath.Join(tmp, "nothing.jsonl"))

	recs, err := readHistory("anything.com", 10)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("got %d records from missing file, want 0", len(recs))
	}
}

func TestReadHistory_MalformedLineTolerated(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "history.jsonl")
	t.Setenv("NETDOC_HISTORY", path)

	// Manually write a mix of malformed + valid lines. The parser should
	// silently skip malformed lines (real-world history.jsonl files can
	// accumulate garbage from crashes / partial writes).
	contents := `not json at all
{"target":"a.com","host":"a.com","healthy":true,"report":{"target":"a.com","host":"a.com","port":443,"scheme":"https","healthy":true,"checks":[],"elapsed":"100ms"}}
{ malformed {
{"target":"a.com","host":"a.com","healthy":false,"report":{"target":"a.com","host":"a.com","port":443,"scheme":"https","healthy":false,"checks":[],"elapsed":"200ms"}}
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	recs, err := readHistory("a.com", 100)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (malformed should be skipped)", len(recs))
	}
}

func TestRenderHistoryTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	renderHistoryTable(&buf, "ghost.example", nil)
	if !strings.Contains(buf.String(), "No history") {
		t.Errorf("empty history should display a placeholder message, got: %q", buf.String())
	}
}

func TestHistoryRecord_JSONRoundTrip(t *testing.T) {
	// Marshal + unmarshal preserves the timestamp and embedded report.
	original := historyRecord{
		Target:  "example.com",
		Host:    "example.com",
		Healthy: true,
		Report: Report{
			Target:  "example.com",
			Host:    "example.com",
			Healthy: true,
			Checks: []Check{
				{Name: "DNS", Status: StatusOK, Summary: "resolved"},
			},
		},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtripped historyRecord
	if err := json.Unmarshal(b, &roundtripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtripped.Target != original.Target {
		t.Errorf("Target lost in round-trip")
	}
	if len(roundtripped.Report.Checks) != 1 {
		t.Errorf("nested checks lost in round-trip")
	}
}
