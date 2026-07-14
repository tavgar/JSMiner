package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCrawlStatsReported verifies crawlBFS reports an accurate run summary
// through OnComplete: pages fetched, in-scope targets discovered, distinct pages
// enqueued and a non-zero duration.
func TestCrawlStatsReported(t *testing.T) {
	// Seed links two same-host pages; one of those links a third. All are distinct
	// shapes so nothing collapses under dedup.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><a href="/a">a</a><a href="/b">b</a></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><h1>a</h1><a href="/c">c</a></html>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><h1>b</h1><p>leaf b</p></html>`)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><h1>c</h1><p>leaf c has words here</p></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false // toy pages share a shape; isolate reachability
	opts.ProbeMethods = false
	opts.DiscoverWellKnown = false

	var got CrawlStats
	var calls int
	opts.OnComplete = func(s CrawlStats) {
		calls++
		got = s
	}

	if _, err := e.ScanURLCrawl(ts.URL, false, false, false, opts); err != nil {
		t.Fatal(err)
	}

	if calls != 1 {
		t.Fatalf("OnComplete called %d times, want exactly 1", calls)
	}
	// Seed + /a + /b + /c are all reachable and distinct → 4 pages fetched.
	if got.PagesFetched != 4 {
		t.Fatalf("PagesFetched = %d, want 4", got.PagesFetched)
	}
	if got.PagesErrored != 0 {
		t.Fatalf("PagesErrored = %d, want 0", got.PagesErrored)
	}
	// Every fetched page is enqueued exactly once (seed + 3).
	if got.Enqueued != 4 {
		t.Fatalf("Enqueued = %d, want 4", got.Enqueued)
	}
	// /a and /b are discovered on the seed, /c on /a → at least 3 targets found.
	if got.TargetsFound < 3 {
		t.Fatalf("TargetsFound = %d, want >= 3", got.TargetsFound)
	}
	if got.Duration <= 0 {
		t.Fatalf("Duration = %v, want > 0", got.Duration)
	}
}

// TestCrawlStatsCountsErrors verifies a page whose fetch fails is counted as an
// error, not a fetch, in the summary.
func TestCrawlStatsCountsErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Link a path the server aborts the connection on, forcing a scan error.
		io.WriteString(w, `<html><a href="/broken">x</a></html>`)
	})
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false
	opts.ProbeMethods = false
	opts.DiscoverWellKnown = false
	SetFetchRetries(0) // don't let retries mask the forced failure
	defer SetFetchRetries(2)

	var got CrawlStats
	opts.OnComplete = func(s CrawlStats) { got = s }
	if _, err := e.ScanURLCrawl(ts.URL, false, false, false, opts); err != nil {
		t.Fatal(err)
	}

	if got.PagesFetched != 1 {
		t.Fatalf("PagesFetched = %d, want 1 (seed only)", got.PagesFetched)
	}
	if got.PagesErrored != 1 {
		t.Fatalf("PagesErrored = %d, want 1 (the aborted /broken)", got.PagesErrored)
	}
}
