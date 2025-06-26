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
		"/v1/test":                   false,
		"./local/api":                false,
		"../parent/api":              false,
		"//cdn.example.com/lib.js":   true,
	}
	for _, e := range eps {
		v, ok := expected[e.Value]
		if !ok {
			t.Fatalf("unexpected endpoint %s", e.Value)
		}
		if v != e.IsURL {
			t.Fatalf("endpoint %s classification mismatch", e.Value)
		}
		delete(expected, e.Value)
	}
	if len(expected) != 0 {
		t.Fatalf("missing endpoints: %v", expected)
	}
}

func TestScanReaderWithEndpoints(t *testing.T) {
	js := `fetch("https://ex.com/api"); axios.get('/v2/data');`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	var urls, paths []string
	for _, m := range matches {
		switch m.Pattern {
		case "endpoint_url":
			urls = append(urls, m.Value)
		case "endpoint_path":
			paths = append(paths, m.Value)
		}
	}
	if len(urls) != 1 || len(paths) != 1 {
		t.Fatalf("expected 1 url and 1 path, got %d and %d", len(urls), len(paths))
	}
}

func TestScanReaderWithEndpointsNonJS(t *testing.T) {
	js := `fetch("/should/ignore")`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if strings.HasPrefix(m.Pattern, "endpoint_") {
			t.Fatalf("did not expect endpoint match for non-js file")
		}
	}
}

func TestScanReaderFiltersInvalidEndpoints(t *testing.T) {
	js := `fetch("http://a"); fetch('/./'); fetch('//'); fetch('/$'); fetch('https://valid.com/api');`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 valid endpoint, got %d", len(matches))
	}
	if matches[0].Value != "https://valid.com/api" {
		t.Fatalf("unexpected endpoint %s", matches[0].Value)
	}
}
