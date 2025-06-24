package scan

import (
	"strings"
	"testing"
)

func TestParseJSPostRequests(t *testing.T) {
	js := `fetch("https://api.example.com/v1", {method:"POST"});
    axios.post('/v2/data');
    $.post("./local");
    $.ajax({url:'../ajax', type:'POST'});
    xhr.open('POST', '//cdn.example.com/u');`
	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 5 {
		t.Fatalf("expected 5 endpoints, got %d", len(eps))
	}
	expected := map[string]bool{
		"https://api.example.com/v1": true,
		"/v2/data":                   false,
		"./local":                    false,
		"../ajax":                    false,
		"//cdn.example.com/u":        true,
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

func TestScanReaderPostRequests(t *testing.T) {
	js := `fetch("https://ex.com/api", {method:'POST'}); axios.post('/submit');`
	e := NewExtractor(true)
	matches, err := e.ScanReaderPostRequests("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	var urls, paths []string
	for _, m := range matches {
		switch m.Pattern {
		case "post_url":
			urls = append(urls, m.Value)
		case "post_path":
			paths = append(paths, m.Value)
		}
	}
	if len(urls) != 1 || len(paths) != 1 {
		t.Fatalf("expected 1 url and 1 path, got %d and %d", len(urls), len(paths))
	}
}

func TestScanReaderPostRequestsNonJS(t *testing.T) {
	js := `fetch('/ignore', {method:'POST'})`
	e := NewExtractor(true)
	matches, err := e.ScanReaderPostRequests("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}
