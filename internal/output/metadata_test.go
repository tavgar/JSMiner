package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tavgar/JSMiner/internal/scan"
)

func TestPrintScanReturnsChecksumAndScanTimeJSON(t *testing.T) {
	matches := []scan.Match{
		{Source: "app.js", Pattern: "jwt", Value: "eyJa.bc.de", Severity: scan.SeverityHigh},
	}
	startedAt := time.Date(2026, time.July, 17, 9, 8, 7, 123000000, time.FixedZone("test", 2*60*60))

	var buf bytes.Buffer
	p := NewPrinter("json", false, false, false, "test")
	if err := p.PrintScan(&buf, matches, startedAt); err != nil {
		t.Fatal(err)
	}

	var out struct {
		Checksum string          `json:"checksum"`
		ScanTime string          `json:"scan_time"`
		Results  json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}
	if out.Checksum != ResultsChecksum(matches) {
		t.Fatalf("checksum = %q, want %q", out.Checksum, ResultsChecksum(matches))
	}
	if len(out.Checksum) != 64 {
		t.Fatalf("checksum should be a SHA-256 hex digest, got %q", out.Checksum)
	}
	if out.ScanTime != "2026-07-17T07:08:07.123Z" {
		t.Fatalf("scan_time = %q, want UTC RFC3339 timestamp", out.ScanTime)
	}
	if string(out.Results) == "" || string(out.Results) == "null" {
		t.Fatalf("results must always be returned, got %s", out.Results)
	}
}

func TestPrintScanJSONRemainsValidWhenBannerEnabled(t *testing.T) {
	var buf bytes.Buffer
	p := NewPrinter("json", true, false, false, "test")
	if err := p.PrintScan(&buf, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	var out struct {
		Checksum string `json:"checksum"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("banner corrupted JSON output %q: %v", buf.String(), err)
	}
	if out.Checksum == "" {
		t.Fatalf("missing checksum in %q", buf.String())
	}
}

func TestPrintScanReturnsMetadataForNoResults(t *testing.T) {
	startedAt := time.Date(2026, time.July, 17, 7, 8, 9, 0, time.UTC)

	for _, format := range []string{"json", "pretty"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			p := NewPrinter(format, false, false, false, "test")
			if err := p.PrintScan(&buf, nil, startedAt); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			if !strings.Contains(out, ResultsChecksum(nil)) {
				t.Fatalf("missing empty-results checksum in %q", out)
			}
			if !strings.Contains(out, "2026-07-17T07:08:09Z") {
				t.Fatalf("missing scan time in %q", out)
			}
			if format == "json" && !strings.Contains(out, `"results":[]`) {
				t.Fatalf("JSON must return an empty results array, got %q", out)
			}
		})
	}
}

func TestResultsChecksumIsOrderIndependent(t *testing.T) {
	const emptySHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
	if got := ResultsChecksum(nil); got != emptySHA256 {
		t.Fatalf("empty result checksum = %q, want SHA-256 of canonical []: %q", got, emptySHA256)
	}

	first := scan.Match{
		Source: "first.js", Pattern: "endpoint_path", Value: "/api", Severity: scan.SeverityInfo,
	}
	second := scan.Match{
		Source: "second.js", Pattern: "jwt", Value: "eyJa.bc.de", Severity: scan.SeverityHigh,
	}

	a := ResultsChecksum([]scan.Match{first, second})
	b := ResultsChecksum([]scan.Match{second, first})
	if a != b {
		t.Fatalf("result order changed checksum: %q != %q", a, b)
	}

	second.Source = "another-source.js"
	second.Snippet = "const token = 'eyJa.bc.de'"
	if got := ResultsChecksum([]scan.Match{first, second}); got != a {
		t.Fatalf("display-only source/snippet changed checksum: %q != %q", got, a)
	}

	second.Value = "eyJx.yz.zz"
	if got := ResultsChecksum([]scan.Match{first, second}); got == a {
		t.Fatal("changing a result value did not change the checksum")
	}
}
