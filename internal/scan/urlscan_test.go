package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test ScanURL follows script references and imports within same host
func TestScanURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/a.js"></script></html>`)
	})
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const t='eyJabc.def.ghi'; import './b.js';`)
	})
	mux.HandleFunc("/b.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('https://api.example.com/v1');`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true)
	matches, err := e.ScanURL(ts.URL, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
	}
	foundJWT := false
	foundEndpoint := false
	for _, m := range matches {
		if m.Pattern == "jwt" {
			foundJWT = true
		}
		if m.Pattern == "endpoint_url" {
			foundEndpoint = true
		}
	}
	if !foundJWT || !foundEndpoint {
		t.Fatalf("missing expected matches: jwt=%v endpoint=%v", foundJWT, foundEndpoint)
	}
}

// Test that ScanURL follows scripts from other hosts when external scanning is enabled.
func TestScanURLExternal(t *testing.T) {
	muxJS := http.NewServeMux()
	muxJS.HandleFunc("/ext.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "fetch('https://api.example.com/v2');")
	})
	tsJS := httptest.NewServer(muxJS)
	defer tsJS.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="`+tsJS.URL+`/ext.js"></script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true)
	matches, err := e.ScanURL(ts.URL, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("expected matches, got none")
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "endpoint_url" && strings.Contains(m.Value, "api.example.com") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find endpoint from external script")
	}
}

// Test ScanURL with rendering to detect dynamically inserted script
func TestScanURLRender(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><script>document.write('<script src="/dyn.js"></script>');</script></head><body></body></html>`)
	})
	mux.HandleFunc("/dyn.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/api/data');`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true)
	matches, err := e.ScanURL(ts.URL, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "endpoint_path" && strings.Contains(m.Value, "/api/data") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected endpoint from dynamic script")
	}
}

// Test that passing endpoints=true filters out non-endpoint matches.
func TestScanURLEndpointsOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const t='eyJabc.def.ghi'; fetch('/api/one');`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/a.js"></script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true)
	matches, err := e.ScanURL(ts.URL, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("expected endpoint matches")
	}
	for _, m := range matches {
		if !strings.HasPrefix(m.Pattern, "endpoint_") {
			t.Fatalf("unexpected non-endpoint pattern %s", m.Pattern)
		}
	}
}
