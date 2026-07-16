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
	if c.skipPage("http://x/", "http://x/", 200, []byte("<html>real homepage</html>")) {
		t.Fatal("seed page must not be skipped")
	}
	// A page matching the learned wildcard (same status/words/lines) is skipped
	// even though its bytes differ.
	if !c.skipPage("http://x/a", "http://x/a", 200, []byte("cannot find that page here now")) {
		t.Fatal("wildcard-matching page should be skipped")
	}
	// A genuinely unique page is accepted the first time...
	uniq := []byte("a wholly distinct page body with several unique words present here today")
	if c.skipPage("http://x/b", "http://x/b", 200, uniq) {
		t.Fatal("unique page should be accepted")
	}
	// ...and skipped as a duplicate the second time.
	if !c.skipPage("http://x/c", "http://x/c", 200, uniq) {
		t.Fatal("duplicate page should be skipped")
	}
}

func TestAutoCalibratorExemptsConfiguredSeedAfterOtherPages(t *testing.T) {
	c := newAutoCalibrator()
	c.setBase("http://x/account/login?session=1")
	catchAll := []byte("cannot find this page here now")
	c.wildcard[pageSig(404, catchAll)] = struct{}{}

	if !c.skipPage("http://x/.well-known/security.txt", "http://x/.well-known/security.txt", 404, catchAll) {
		t.Fatal("non-seed wildcard page should be skipped even when processed first")
	}
	if c.skipPage("http://x/account/login?session=1", "http://x/account/login", 200, catchAll) {
		t.Fatal("configured seed must be accepted after another page is processed")
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

// TestScanURLCrawlAutoCalibratePerLevel checks that a catch-all confined to a
// sub-directory — one the root probe never sees — is still learned and
// suppressed. The root answers unknown paths with a short 404; only /api/*
// returns the (secret-carrying) shell, so suppression must come from probing
// the /api/ level, not the root.
func TestScanURLCrawlAutoCalibratePerLevel(t *testing.T) {
	const rootMiss = `<html><body>not here</body></html>`
	const apiCatchAll = `<html><body>the requested api resource could not be located on this server</body>` +
		`<script>var k="AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac";</script></html>`

	// The two shells must have distinct signatures, otherwise the root wildcard
	// alone would explain the suppression and the test would prove nothing.
	if pageSig(200, []byte(rootMiss)) == pageSig(200, []byte(apiCatchAll)) {
		t.Fatal("test setup: root and /api catch-all must have different signatures")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/api/ghost');`)
	})
	// Everything under /api/ is the same section catch-all.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, apiCatchAll)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			io.WriteString(w, `<html><head><script src="/app.js"></script></head><body>home</body></html>`)
			return
		}
		io.WriteString(w, rootMiss)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	plain, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, CrawlOptions{MaxDepth: 2, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(plain, "google_api") {
		t.Fatalf("expected the /api catch-all secret without -ac, got %+v", plain)
	}

	acOpts := CrawlOptions{MaxDepth: 2, SameScopeOnly: true, AutoCalibrate: true}
	calibrated, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, acOpts)
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(calibrated, "google_api") {
		t.Fatalf("per-level calibration should have suppressed the /api catch-all, got %+v", calibrated)
	}
}
