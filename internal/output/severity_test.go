package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tavgar/JSMiner/internal/scan"
)

// TestPrintRanksBySeverityJSON verifies findings are emitted High -> Medium ->
// Info regardless of discovery order, with the stable order kept within a band.
func TestPrintRanksBySeverityJSON(t *testing.T) {
	matches := []scan.Match{
		{Pattern: "email", Value: "a@b.com", Severity: scan.SeverityInfo},
		{Pattern: "api_key", Value: "api_key=xxxx", Severity: scan.SeverityMedium},
		{Pattern: "github_token", Value: "ghp_x", Severity: scan.SeverityHigh},
		{Pattern: "endpoint_path", Value: "/api", Severity: scan.SeverityInfo},
		{Pattern: "password", Value: "password: hunter2", Severity: scan.SeverityMedium},
	}
	var buf bytes.Buffer
	p := NewPrinter("json", false, false, false, "test")
	if err := p.Print(&buf, matches); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Results []struct {
			Pattern  string `json:"pattern"`
			Severity string `json:"severity"`
		} `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}

	wantSeverity := []string{
		scan.SeverityHigh,
		scan.SeverityMedium, scan.SeverityMedium,
		scan.SeverityInfo, scan.SeverityInfo,
	}
	if len(out.Results) != len(wantSeverity) {
		t.Fatalf("expected %d entries, got %d: %+v", len(wantSeverity), len(out.Results), out.Results)
	}
	for i, sev := range wantSeverity {
		if out.Results[i].Severity != sev {
			t.Fatalf("entry %d: want severity %q, got %q (%+v)", i, sev, out.Results[i].Severity, out.Results)
		}
	}
	// Stable order within the Medium band: api_key was discovered before password.
	if out.Results[1].Pattern != "api_key" || out.Results[2].Pattern != "password" {
		t.Fatalf("medium band lost discovery order: %+v", out.Results)
	}
	// Stable order within the Info band: email before endpoint_path.
	if out.Results[3].Pattern != "email" || out.Results[4].Pattern != "endpoint_path" {
		t.Fatalf("info band lost discovery order: %+v", out.Results)
	}
}

// TestPrintRanksBySeverityPretty verifies the pretty output leads with the
// highest-severity finding.
func TestPrintRanksBySeverityPretty(t *testing.T) {
	matches := []scan.Match{
		{Pattern: "email", Value: "a@b.com", Severity: scan.SeverityInfo},
		{Pattern: "github_token", Value: "ghp_x", Severity: scan.SeverityHigh},
	}
	var buf bytes.Buffer
	p := NewPrinter("pretty", false, false, false, "test")
	if err := p.Print(&buf, matches); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if hi, info := strings.Index(out, "ghp_x"), strings.Index(out, "a@b.com"); hi < 0 || info < 0 || hi > info {
		t.Fatalf("high finding should print before info finding:\n%s", out)
	}
}
