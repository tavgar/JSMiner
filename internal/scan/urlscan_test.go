package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

	e := NewExtractor(true, false)
	matches, err := e.ScanURL(ts.URL, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Expected: jwt (a.js) + endpoint_path "./b.js" (a.js import) + endpoint_url
	// api.example.com/v1 (b.js) + endpoint_url .../a.js (the <script src> the page
	// markup references, now harvested by HTML link extraction).
	if len(matches) != 4 {
		t.Fatalf("expected 4 matches, got %d: %+v", len(matches), matches)
	}
	foundJWT := false
	foundEndpoint := false
	foundScriptLink := false
	for _, m := range matches {
		if m.Pattern == "jwt" {
			foundJWT = true
		}
		if m.Pattern == "endpoint_url" && strings.Contains(m.Value, "api.example.com/v1") {
			foundEndpoint = true
		}
		if m.Pattern == "endpoint_url" && strings.HasSuffix(m.Value, "/a.js") {
			foundScriptLink = true
		}
	}
	if !foundJWT || !foundEndpoint || !foundScriptLink {
		t.Fatalf("missing expected matches: jwt=%v endpoint=%v scriptLink=%v", foundJWT, foundEndpoint, foundScriptLink)
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

	e := NewExtractor(true, false)
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

// TestScanURLRedirectHonorsExternal verifies scope is enforced before a redirect
// request is sent. A post-response final-URL check is too late: the external body
// would already have been fetched and scanned.
func TestScanURLRedirectHonorsExternal(t *testing.T) {
	const key = "AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac"
	var externalHits int64
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&externalHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const key="`+key+`";`)
	}))
	defer externalServer.Close()
	// The servers share an IP in tests; use a different hostname so sameScope
	// treats the redirect as external while it still resolves locally.
	externalURL := strings.Replace(externalServer.URL, "127.0.0.1", "localhost", 1)

	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalURL+"/outside.js", http.StatusFound)
	}))
	defer seed.Close()

	e := NewExtractor(false, false)
	restricted, err := e.ScanURL(seed.URL+"/inside.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&externalHits); got != 0 {
		t.Fatalf("external=false sent %d request(s) to an off-scope redirect", got)
	}
	if hasPattern(restricted, "google_api") {
		t.Fatal("external=false scanned the off-scope redirect body")
	}

	allowed, err := e.ScanURL(seed.URL+"/inside.js", false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&externalHits); got != 1 {
		t.Fatalf("external=true sent %d request(s) to the redirect target, want 1", got)
	}
	if !hasPattern(allowed, "google_api") {
		t.Fatal("external=true did not scan the external redirect target")
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

	e := NewExtractor(true, false)
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

func TestScanURLRecognizesMixedCaseHTMLContentType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Text/HTML; Charset=UTF-8")
		io.WriteString(w, `<html><script src="/app.js"></script></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch("/api/mixed-case")`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	ms, err := e.ScanURL(ts.URL, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(ms, "endpoint_path") {
		t.Fatalf("mixed-case HTML Content-Type prevented script discovery: %+v", ms)
	}
}

func TestScanURLExtensionlessJavaScriptUsesContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Application/JavaScript; Charset=UTF-8")
		io.WriteString(w, `fetch("/api/extensionless")`)
	}))
	defer ts.Close()

	e := NewExtractor(true, false)
	ms, err := e.ScanURL(ts.URL+"/bundle", true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(ms, "endpoint_path") {
		t.Fatalf("extensionless JavaScript response yielded no endpoint: %+v", ms)
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

	e := NewExtractor(true, false)
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

func TestScanURLInlineScript(t *testing.T) {
	key := "AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script>var apiKey="`+key+`";</script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	matches, err := e.ScanURL(ts.URL, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "google_api" && strings.Contains(m.Value, key) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected google_api match in inline script, got %+v", matches)
	}
}
