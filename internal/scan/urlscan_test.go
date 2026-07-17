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
	var externalHits int64
	muxJS := http.NewServeMux()
	muxJS.HandleFunc("/ext.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&externalHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "fetch('https://api.example.com/v2');")
	})
	tsJS := httptest.NewServer(muxJS)
	defer tsJS.Close()
	externalJSURL := strings.Replace(tsJS.URL, "127.0.0.1", "localhost", 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="`+externalJSURL+`/ext.js"></script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	restricted, err := e.ScanURL(ts.URL, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&externalHits); got != 0 {
		t.Fatalf("external=false requested the external script %d time(s)", got)
	}
	for _, m := range restricted {
		if m.Pattern == "endpoint_url" && strings.Contains(m.Value, "api.example.com") {
			t.Fatal("external=false scanned the external script body")
		}
	}

	matches, err := e.ScanURL(ts.URL, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&externalHits); got != 1 {
		t.Fatalf("external=true requested the external script %d time(s), want 1", got)
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

// TestScanURLRedirectIndependentFromExternal verifies redirect following has its
// own switch. -external selects page-referenced sources and must neither enable
// nor disable redirects. A blocked redirect's response body is still scanned,
// but its destination is never requested.
func TestScanURLRedirectIndependentFromExternal(t *testing.T) {
	const externalKey = "AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac"
	const redirectBodyJWT = "eyJredirect.body.token"
	var externalHits int64
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&externalHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const key="`+externalKey+`";`)
	}))
	defer externalServer.Close()
	// Use a different hostname to make the redirect visibly cross-domain while
	// still resolving to the local test server.
	externalURL := strings.Replace(externalServer.URL, "127.0.0.1", "localhost", 1)

	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Location", externalURL+"/outside.js")
		w.WriteHeader(http.StatusFound)
		io.WriteString(w, `<html><script>const token="`+redirectBodyJWT+`";</script></html>`)
	}))
	defer seed.Close()

	SetFollowRedirects(false)
	t.Cleanup(func() { SetFollowRedirects(false) })

	e := NewExtractor(false, false)
	for _, external := range []bool{false, true} {
		// Keep rendering enabled to prove the renderer does not navigate back to
		// the original URL and follow the redirect behind the HTTP policy.
		blocked, err := e.ScanURL(seed.URL+"/inside.js", false, external, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := atomic.LoadInt64(&externalHits); got != 0 {
			t.Fatalf("redirect=false, external=%t sent %d request(s) to redirect destination", external, got)
		}
		if !hasPattern(blocked, "jwt") {
			t.Fatalf("redirect=false, external=%t did not scan the redirect response body", external)
		}
		if hasPattern(blocked, "google_api") {
			t.Fatalf("redirect=false, external=%t scanned the redirect destination body", external)
		}
	}

	SetFollowRedirects(true)
	allowed, err := e.ScanURL(seed.URL+"/inside.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&externalHits); got != 1 {
		t.Fatalf("redirect=true sent %d request(s) to the redirect destination, want 1", got)
	}
	if !hasPattern(allowed, "google_api") {
		t.Fatal("redirect=true did not scan the redirect destination with external=false")
	}
}

// TestScanURLRedirectDisabledBlocksSameHost verifies the redirect switch blocks
// every hop, not just cross-domain hops.
func TestScanURLRedirectDisabledBlocksSameHost(t *testing.T) {
	var destinationHits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/destination", http.StatusFound)
	})
	mux.HandleFunc("/destination", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&destinationHits, 1)
		io.WriteString(w, "destination")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	SetFollowRedirects(false)
	t.Cleanup(func() { SetFollowRedirects(false) })

	e := NewExtractor(false, false)
	if _, err := e.ScanURL(srv.URL+"/start", false, true, false); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&destinationHits); got != 0 {
		t.Fatalf("redirect=false sent %d request(s) to a same-host destination", got)
	}

	SetFollowRedirects(true)
	if _, err := e.ScanURL(srv.URL+"/start", false, true, false); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&destinationHits); got != 1 {
		t.Fatalf("redirect=true sent %d request(s) to a same-host destination, want 1", got)
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
