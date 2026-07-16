package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSkipContentDedup unit-tests the body-hash dedup: the first sighting of a
// body is admitted, an identical body afterwards is skipped, and a different body
// is admitted.
func TestSkipContentDedup(t *testing.T) {
	c := newAutoCalibrator()
	bundle := []byte("var t='secret';\nfunction f(){return 1}")
	if c.skipContent(bundle) {
		t.Fatal("first sighting of a body should be scanned, not skipped")
	}
	if !c.skipContent(bundle) {
		t.Fatal("identical body should be skipped on the second sighting")
	}
	if c.skipContent([]byte("var t='different';")) {
		t.Fatal("a different body should be scanned, not skipped")
	}
}

// TestScanURLCrawlContentDedupKeepsReachability verifies that when the same bundle
// bytes appear under two different names/paths, the crawl still follows the second
// copy's imports even though its body scan is skipped as a duplicate — so a
// relative chunk unique to the second copy's path is not lost. Both pages link an
// identical bundle (same bytes) sitting at a different path; each bundle imports a
// path-relative chunk carrying its own distinct secret.
func TestScanURLCrawlContentDedupKeepsReachability(t *testing.T) {
	const (
		mainJWT   = "eyJhbGciOiJIUzI1NiJ9.eyJtYWluIjoxMjN9.mainSignatureAAAA"
		chunkXJWT = "eyJhbGciOiJIUzI1NiJ9.eyJjaHVua1giOjF9.chunkXSignatureBB"
		chunkYJWT = "eyJhbGciOiJIUzI1NiJ9.eyJjaHVua1kiOjF9.chunkYSignatureCC"
	)
	// Identical bytes for both bundles: same JWT, same relative import specifier.
	// Because they live at /x/ and /y/, "./chunk.js" resolves to a different chunk
	// for each, so following the import after a dedup skip is what reaches /y/chunk.
	bundleBody := "import './chunk.js';\nvar token='" + mainJWT + "';"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `<html><body><a href="/pageA">A</a><a href="/pageB">B</a></body></html>`)
		case "/pageA":
			io.WriteString(w, `<html><body><h1>alpha section</h1><script src="/x/app.aaaa.js"></script></body></html>`)
		case "/pageB":
			io.WriteString(w, `<html><body><h1>bravo section here</h1><script src="/y/app.bbbb.js"></script></body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<html><body>not found here now</body></html>`)
		}
	})
	js := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/x/app.aaaa.js", js(bundleBody))
	mux.HandleFunc("/y/app.bbbb.js", js(bundleBody))
	mux.HandleFunc("/x/chunk.js", js("var a='"+chunkXJWT+"';"))
	mux.HandleFunc("/y/chunk.js", js("var b='"+chunkYJWT+"';"))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	// AutoCalibrate on so the calibrator (which backs content dedup) is installed.
	opts := CrawlOptions{MaxDepth: 2, MaxPages: 50, SameScopeOnly: true, AutoCalibrate: true}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}

	found := func(val string) bool {
		for _, m := range ms {
			if m.Value == val {
				return true
			}
		}
		return false
	}
	if !found(mainJWT) {
		t.Error("main bundle JWT not found")
	}
	if !found(chunkXJWT) {
		t.Error("chunk X JWT not found (import from first bundle)")
	}
	if !found(chunkYJWT) {
		t.Error("chunk Y JWT not found — the deduped bundle's import was not followed")
	}
}
