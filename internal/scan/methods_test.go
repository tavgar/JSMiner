package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gatheredMethods returns the methods recorded for the gathered-URL finding whose
// Value equals url, or "" if there is none.
func gatheredMethods(ms []Match, url string) string {
	for _, m := range ms {
		if m.Pattern == GatheredURLPattern && m.Value == url {
			return m.Params
		}
	}
	return ""
}

func TestNormalizeMethods(t *testing.T) {
	got := normalizeMethods(nil)
	if len(got) == 0 || got[0] != "GET" {
		t.Fatalf("default methods should start with GET, got %v", got)
	}
	got = normalizeMethods([]string{"post", "GET", "post"})
	want := []string{"GET", "POST"}
	if !equalStrings(got, want) {
		t.Fatalf("normalizeMethods dedup/upper/order = %v, want %v", got, want)
	}
}

func TestMethodWorks(t *testing.T) {
	if methodWorks(nil, "POST", "http://x/a", 405, nil) {
		t.Fatal("405 must never count as working")
	}
	if methodWorks(nil, "GET", "http://x/a", 500, nil) {
		t.Fatal("5xx must not count as working")
	}
	if !methodWorks(nil, "GET", "http://x/a", 200, []byte("ok")) {
		t.Fatal("200 with no calibrator should count as working")
	}
}

// TestScanURLCrawlGathersMethods verifies the end-to-end feature: a crawl reports,
// per URL, which request verbs worked — GET on a read-only page, and both GET and
// POST on an endpoint that accepts POST.
func TestScanURLCrawlGathersMethods(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			io.WriteString(w, `<html><script>fetch('/api/submit');</script></html>`)
			return
		}
		// /api/submit accepts GET and POST; everything else is a 404 shell so the
		// per-method calibration has a catch-all to learn.
		if r.URL.Path == "/api/submit" {
			io.WriteString(w, `<html><body>submit ok `+r.Method+`</body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `<html><body>no such path `+r.URL.Path+`</body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false // isolate method probing from page suppression
	opts.ParamReplay = false
	ms, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}

	seed := gatheredMethods(ms, ts.URL+"/")
	if !strings.Contains(seed, "GET") {
		t.Fatalf("seed should report GET as working, got %q", seed)
	}
	submit := gatheredMethods(ms, ts.URL+"/api/submit")
	if !strings.Contains(submit, "GET") || !strings.Contains(submit, "POST") {
		t.Fatalf("/api/submit should report GET and POST, got %q", submit)
	}
}

// TestScanURLCrawlMethodCatchAll verifies that per-method error logic suppresses a
// verb: a level that answers unknown POSTs with a stable 405 shell must not report
// POST as "working" for a real page under that level.
func TestScanURLCrawlMethodCatchAll(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			io.WriteString(w, `<html><script>fetch('/read/page');</script></html>`)
		case r.Method == "POST":
			// The /read/ level rejects every POST with the same 405 shell.
			w.WriteHeader(http.StatusMethodNotAllowed)
			io.WriteString(w, `<html><body>method not allowed on this read only section</body></html>`)
		case r.URL.Path == "/read/page":
			// A genuine, content-rich page distinct from the level's GET catch-all.
			io.WriteString(w, `<html><body>the quarterly report has many distinct words here today and tomorrow and beyond for readers everywhere across the site</body></html>`)
		default:
			// Unknown GET paths get a short, uniform shell so GET calibration learns
			// a catch-all that the real page above does not match.
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<html><body>missing</body></html>`)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false
	opts.ParamReplay = false
	ms, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}

	page := gatheredMethods(ms, ts.URL+"/read/page")
	if page == "" {
		t.Fatal("expected a gathered-URL finding for /read/page")
	}
	if strings.Contains(page, "POST") {
		t.Fatalf("POST is rejected on /read/ and must not be reported, got %q", page)
	}
	if !strings.Contains(page, "GET") {
		t.Fatalf("GET should still be reported for /read/page, got %q", page)
	}
}

func TestParamReplayerObserve(t *testing.T) {
	r := newParamReplayer("http://x", 0)
	// First page: one param, levels /a/ and /.
	out := r.observe([]string{"user=1"}, []string{"http://x/a/b", "http://x/"})
	// Levels discovered: /a/ and / (root). New param pairs with 0 old levels, then
	// new levels pair with the param -> 2 replays.
	if len(out) != 2 {
		t.Fatalf("expected 2 replays, got %d: %+v", len(out), out)
	}
	// A second page contributing a new level pairs with the existing param.
	out = r.observe(nil, []string{"http://x/c/"})
	if len(out) != 1 || out[0].url != "http://x/c/" || out[0].params != "user=1" {
		t.Fatalf("new level should replay the known param, got %+v", out)
	}
	// Nothing new -> nothing emitted.
	if got := r.observe(nil, []string{"http://x/a/x"}); len(got) != 0 {
		t.Fatalf("already-known level should emit nothing, got %+v", got)
	}
}

func TestParamReplayerMax(t *testing.T) {
	r := newParamReplayer("http://x", 1)
	out := r.observe([]string{"a=1", "b=2"}, []string{"http://x/one/", "http://x/two/"})
	if len(out) != 1 {
		t.Fatalf("max=1 should cap replays at 1, got %d", len(out))
	}
}
