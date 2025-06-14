package scan

import (
	"strings"
	"testing"
)

func TestParseJSEndpoints(t *testing.T) {
	js := `const a = "https://api.example.com/v1";
    fetch('/v1/test');
    fetch("./local/api");
    fetch('../parent/api');
    fetch("//cdn.example.com/lib.js");`
	eps := parseJSEndpoints([]byte(js))
	if len(eps) != 5 {
		t.Fatalf("expected 5 endpoints, got %d", len(eps))
	}
	expected := map[string]bool{
		"https://api.example.com/v1": true,
		"/v1/test":                   true,
		"./local/api":                true,
		"../parent/api":              true,
		"//cdn.example.com/lib.js":   true,
	}
	for _, e := range eps {
		if !expected[e] {
			t.Fatalf("unexpected endpoint %s", e)
		}
	}
}

func TestScanReaderWithEndpoints(t *testing.T) {
	js := `fetch("https://ex.com/api"); axios.get('/v2/data');`
	e := NewExtractor(true)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	var endpoints []string
	for _, m := range matches {
		if m.Pattern == "endpoint" {
			endpoints = append(endpoints, m.Value)
		}
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestScanReaderWithEndpointsNonJS(t *testing.T) {
	js := `fetch("/should/ignore")`
	e := NewExtractor(true)
	matches, err := e.ScanReaderWithEndpoints("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if m.Pattern == "endpoint" {
			t.Fatalf("did not expect endpoint match for non-js file")
		}
	}
}
