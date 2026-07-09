package scan

import (
	"strings"
	"testing"
)

func TestScanReaderWithEndpointsAttachesSnippetsWhenEnabled(t *testing.T) {
	// Padding longer than snippetRadius on each side guarantees the captured
	// window is a bounded slice marked with an ellipsis.
	pad := strings.Repeat(".", 300)
	src := `var head="` + pad + `";const key="AIzaSyA1234567890abcdefghijklmnopqrstuvw";var tail="` + pad + `";`

	e := NewExtractor(false, false)
	e.SetSnippet(true)
	ms, err := e.ScanReaderWithEndpoints("app.js", strings.NewReader(src))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var found *Match
	for i := range ms {
		if ms[i].Pattern == "google_api" {
			found = &ms[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a google_api match, got %+v", ms)
	}
	if found.Snippet == "" {
		t.Fatalf("expected a snippet to be attached, got none")
	}
	if !strings.Contains(found.Snippet, found.Value) {
		t.Errorf("snippet should contain the matched value; snippet=%q value=%q", found.Snippet, found.Value)
	}
	// The window is bounded, so the long surrounding padding must be truncated
	// with an ellipsis rather than captured whole.
	if !strings.Contains(found.Snippet, "…") {
		t.Errorf("expected a bounded window marked with an ellipsis, got:\n%s", found.Snippet)
	}
}

func TestScanReaderWithEndpointsNoSnippetByDefault(t *testing.T) {
	src := `const key="AIzaSyA1234567890abcdefghijklmnopqrstuvw";`

	e := NewExtractor(false, false)
	ms, err := e.ScanReaderWithEndpoints("app.js", strings.NewReader(src))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, m := range ms {
		if m.Snippet != "" {
			t.Errorf("snippet should be empty unless enabled, got %q for %s", m.Snippet, m.Pattern)
		}
	}
}
