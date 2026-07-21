package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tavgar/JSMiner/internal/scan"
)

func sampleReport() Report {
	return Report{
		Matches: []scan.Match{
			{Source: "https://app.test/app.js", Pattern: "aws_key", Value: "AKIA...", Severity: scan.SeverityHigh},
		},
		DOM: []scan.DOMFinding{
			{
				Type: scan.DOMTypeFlow, Target: "https://app.test", PageURL: "https://app.test/s?q=x",
				Source:  &scan.DOMSource{Kind: scan.SourceURLQuery, Name: "q"},
				Sink:    &scan.DOMSink{Name: "eval", Argument: 0},
				ProbeID: "url_query:q", Context: "js", Severity: scan.SeverityHigh, Confidence: scan.ConfidenceHigh,
				Fingerprint: "abc123",
			},
			{
				Type: scan.DOMTypeWebMessage, Target: "https://app.test", PageURL: "https://app.test/",
				Message:  &scan.DOMMessageInfo{ListenerCount: 1, OriginChecked: false},
				Severity: scan.SeverityInfo, Confidence: scan.ConfidenceMedium, Fingerprint: "def456",
			},
		},
		DOMSummary: &scan.DOMScanSummary{
			SchemaVersion: scan.DOMSchemaVersion, Mode: "canary", PagesScanned: 1, ProbesSent: 7,
			ProbesLimit: 1000, Findings: 2, FindingsBySeverity: map[string]int{"high": 1, "info": 1},
		},
		ScanTime: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	}
}

// TestJSONLValidAndClean proves the streaming format: one complete JSON object
// per line, a leading scan_meta with schema_version, a trailing scan_summary,
// and no banner or diagnostic text on the stream even with the banner enabled.
func TestJSONLValidAndClean(t *testing.T) {
	var buf bytes.Buffer
	p := NewPrinter("jsonl", true /*banner*/, true /*showSource*/, false, "0.01v")
	if err := p.PrintReport(&buf, sampleReport()); err != nil {
		t.Fatalf("PrintReport: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "JSMiner") || strings.Contains(out, "Bijî") {
		t.Fatalf("banner leaked into jsonl stream:\n%s", out)
	}

	lines := splitNonEmpty(out)
	// meta + 1 match + 2 dom + summary
	if len(lines) != 5 {
		t.Fatalf("expected 5 records, got %d:\n%s", len(lines), out)
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i, err, line)
		}
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &meta)
	if meta["type"] != recordTypeMeta || meta["schema_version"] != JSONLSchemaVersion {
		t.Errorf("first record must be scan_meta with schema_version, got %v", meta)
	}
	var summary map[string]any
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &summary)
	if summary["type"] != recordTypeSummary {
		t.Errorf("last record must be scan_summary, got %v", summary["type"])
	}
	if summary["schema_version"] != JSONLSchemaVersion {
		t.Errorf("summary missing schema_version")
	}
}

// TestJSONWithDOMValid proves the json format carries DOM detail as a superset
// document while staying valid JSON with no banner.
func TestJSONWithDOMValid(t *testing.T) {
	var buf bytes.Buffer
	p := NewPrinter("json", true, false, false, "0.01v")
	if err := p.PrintReport(&buf, sampleReport()); err != nil {
		t.Fatalf("PrintReport: %v", err)
	}
	if strings.Contains(buf.String(), "JSMiner") {
		t.Fatal("banner leaked into json output")
	}
	var doc jsonReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json output invalid: %v\n%s", err, buf.String())
	}
	if len(doc.DOMFindings) != 2 {
		t.Errorf("expected 2 dom findings, got %d", len(doc.DOMFindings))
	}
	if doc.DOMSummary == nil || doc.SchemaVersion == "" {
		t.Error("json superset missing dom_summary or schema_version")
	}
}

// TestJSONNoDOMBackwardCompatible proves an ordinary scan (no DOM findings)
// keeps the exact legacy json structure: no dom_findings, no schema_version.
func TestJSONNoDOMBackwardCompatible(t *testing.T) {
	r := Report{Matches: []scan.Match{{Pattern: "email", Value: "a@b.c", Severity: scan.SeverityInfo}}, ScanTime: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)}
	var viaReport, viaScan bytes.Buffer
	p := NewPrinter("json", false, false, false, "0.01v")
	if err := p.PrintReport(&viaReport, r); err != nil {
		t.Fatal(err)
	}
	p2 := NewPrinter("json", false, false, false, "0.01v")
	if err := p2.PrintScan(&viaScan, r.Matches, r.ScanTime); err != nil {
		t.Fatal(err)
	}
	if viaReport.String() != viaScan.String() {
		t.Errorf("json report path diverged from legacy PrintScan:\n report=%s\n scan=%s", viaReport.String(), viaScan.String())
	}
	if strings.Contains(viaReport.String(), "dom_findings") || strings.Contains(viaReport.String(), "schema_version") {
		t.Error("ordinary json scan must not gain DOM fields")
	}
}

// TestPrettyNoDOMBackwardCompatible proves the pretty report path is identical
// to legacy PrintScan when no DOM findings exist.
func TestPrettyNoDOMBackwardCompatible(t *testing.T) {
	r := Report{Matches: []scan.Match{{Pattern: "email", Value: "a@b.c", Severity: scan.SeverityInfo}}, ScanTime: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)}
	var viaReport, viaScan bytes.Buffer
	NewPrinter("pretty", false, false, false, "0.01v").PrintReport(&viaReport, r)
	NewPrinter("pretty", false, false, false, "0.01v").PrintScan(&viaScan, r.Matches, r.ScanTime)
	if viaReport.String() != viaScan.String() {
		t.Errorf("pretty report path diverged from legacy PrintScan:\n report=%q\n scan=%q", viaReport.String(), viaScan.String())
	}
}

// TestPrettyWithDOMSection proves the human format gains a clearly-delimited DOM
// section and summary line when DOM findings exist.
func TestPrettyWithDOMSection(t *testing.T) {
	var buf bytes.Buffer
	NewPrinter("pretty", false, false, false, "0.01v").PrintReport(&buf, sampleReport())
	out := buf.String()
	if !strings.Contains(out, "=== DOM Findings ===") {
		t.Error("missing DOM findings section header")
	}
	if !strings.Contains(out, "url_query[q] -> eval") {
		t.Errorf("missing source->sink rendering:\n%s", out)
	}
	if !strings.Contains(out, "[dom]") {
		t.Error("missing dom summary line")
	}
}

// TestMatchFingerprintStable proves identical findings hash identically and
// differing ones do not.
func TestMatchFingerprintStable(t *testing.T) {
	a := scan.Match{Pattern: "p", Value: "v", Severity: "high", Source: "s"}
	b := scan.Match{Pattern: "p", Value: "v", Severity: "high", Source: "s"}
	if matchFingerprint(a) != matchFingerprint(b) {
		t.Error("identical matches must share a fingerprint")
	}
	c := scan.Match{Pattern: "p", Value: "w", Severity: "high", Source: "s"}
	if matchFingerprint(a) == matchFingerprint(c) {
		t.Error("differing matches must not share a fingerprint")
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
