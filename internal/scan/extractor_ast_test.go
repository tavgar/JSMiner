package scan

import (
	"strings"
	"testing"
)

func TestScanReaderASTVar(t *testing.T) {
	src := `const t = "eyJabc.def.ghi"`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderAST("script.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}

func TestScanReaderASTConcat(t *testing.T) {
	src := `const t = "eyJabc." + "def.ghi"`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderAST("script.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}

// TestNormalScanUsesASTConcat verifies the AST/value pass is part of the normal
// scanner rather than an isolated API. Production keys are commonly assembled
// from literals to avoid appearing as one raw substring in a bundle.
func TestNormalScanUsesASTConcat(t *testing.T) {
	src := `const key = "AIzaSyD1ad_UKyHFErf" + "LeO_3aoBoNrX1W4bsmac";`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "google_api") {
		t.Fatalf("normal scan missed concatenated Google API key: %+v", matches)
	}
}

func TestQueryVersionedJavaScriptIsRecognized(t *testing.T) {
	src := `const key = "AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac"; fetch("/api/query-js");`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("https://example.com/app.js?v=42#asset", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "google_api") || !hasPattern(matches, "endpoint_path") {
		t.Fatalf("query-versioned JavaScript was not fully scanned: %+v", matches)
	}
}
