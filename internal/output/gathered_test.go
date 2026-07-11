package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tavgar/JSMiner/internal/scan"
)

// TestPrintGatheredSegmentPretty verifies the gathered URLs render as their own
// labelled segment beneath the normal findings.
func TestPrintGatheredSegmentPretty(t *testing.T) {
	matches := []scan.Match{
		{Pattern: "gathered_url", Value: "http://x/api", Params: "methods=GET,POST", Severity: "info"},
		{Pattern: "jwt", Value: "eyJa.bc.de", Severity: "info"},
	}
	var buf bytes.Buffer
	p := NewPrinter("pretty", false, false, false, "test")
	if err := p.Print(&buf, matches); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	hdr := strings.Index(out, "Gathered URLs")
	jwt := strings.Index(out, "eyJa.bc.de")
	url := strings.Index(out, "http://x/api")
	if hdr < 0 || jwt < 0 || url < 0 {
		t.Fatalf("missing expected content:\n%s", out)
	}
	if !(jwt < hdr && hdr < url) {
		t.Fatalf("gathered segment should follow findings and sit under the header:\n%s", out)
	}
}

// TestPrintGatheredSegmentJSON verifies the JSON array orders gathered URLs after
// the normal findings.
func TestPrintGatheredSegmentJSON(t *testing.T) {
	matches := []scan.Match{
		{Pattern: "gathered_url", Value: "http://x/api", Params: "methods=GET", Severity: "info"},
		{Pattern: "jwt", Value: "eyJa.bc.de", Severity: "info"},
	}
	var buf bytes.Buffer
	p := NewPrinter("json", false, false, false, "test")
	if err := p.Print(&buf, matches); err != nil {
		t.Fatal(err)
	}
	var out []struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if out[0].Pattern != "jwt" || out[1].Pattern != "gathered_url" {
		t.Fatalf("gathered_url should be ordered last, got %+v", out)
	}
}
