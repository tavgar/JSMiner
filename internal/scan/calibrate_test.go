package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPageSig(t *testing.T) {
	// Soft-404 pages that only differ by the echoed path share a signature.
	a := pageSig(200, []byte("Cannot GET /alpha"))
	b := pageSig(200, []byte("Cannot GET /bravo"))
	if a != b {
		t.Fatalf("path-echo pages should share a signature: %q vs %q", a, b)
	}
	// Status is part of the signature.
	if pageSig(200, []byte("x")) == pageSig(404, []byte("x")) {
		t.Fatal("different status codes must not share a signature")
	}
	// Different shapes differ.
	if pageSig(200, []byte("one two three")) == pageSig(200, []byte("one\ntwo")) {
		t.Fatal("different word/line counts must not share a signature")
	}
}

func TestAutoCalibratorSkipPage(t *testing.T) {
	c := newAutoCalibrator()
	c.wildcard[pageSig(200, []byte("cannot find this page here now"))] = struct{}{}

	// The first page (seed) is always accepted, even if it looks like anything.
	if c.skipPage(200, []byte("<html>real homepage</html>")) {
		t.Fatal("seed page must not be skipped")
	}
	// A page matching the learned wildcard (same status/words/lines) is skipped
	// even though its bytes differ.
	if !c.skipPage(200, []byte("cannot find that page here now")) {
		t.Fatal("wildcard-matching page should be skipped")
	}
	// A genuinely unique page is accepted the first time...
	uniq := []byte("a wholly distinct page body with several unique words present here today")
	if c.skipPage(200, uniq) {
		t.Fatal("unique page should be accepted")
	}
	// ...and skipped as a duplicate the second time.
	if !c.skipPage(200, uniq) {
		t.Fatal("duplicate page should be skipped")
	}
}

// TestScanURLCrawlAutoCalibrate checks the end-to-end effect: a site whose
// unknown paths all return the same catch-all page (carrying a secret) yields
// that secret on a normal crawl but not when -ac suppresses the catch-all.
func TestScanURLCrawlAutoCalibrate(t *testing.T) {
	const catchAll = `<html><body>page not found here</body>` +
		`<script>var k="AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac";</script></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/x');fetch('/y');`)
	})
	// The seed is a real page; every other path returns the catch-all.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			io.WriteString(w, `<html><head><script src="/app.js"></script></head><body>home</body></html>`)
			return
		}
		io.WriteString(w, catchAll)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	plain, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, CrawlOptions{MaxDepth: 2, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(plain, "google_api") {
		t.Fatalf("expected the catch-all secret without -ac, got %+v", plain)
	}

	var learned int
	acOpts := CrawlOptions{MaxDepth: 2, SameScopeOnly: true, AutoCalibrate: true,
		OnCalibrated: func(n int) { learned = n }}
	calibrated, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, acOpts)
	if err != nil {
		t.Fatal(err)
	}
	if learned == 0 {
		t.Fatal("expected auto-calibration to learn a wildcard signature")
	}
	if hasPattern(calibrated, "google_api") {
		t.Fatalf("auto-calibration should have suppressed the catch-all page, got %+v", calibrated)
	}
}
