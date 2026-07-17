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

func TestProbeURLMethodsReusesFetchedGETBaseline(t *testing.T) {
	var getHits, postHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHits++
		case http.MethodPost:
			postHits++
		}
		io.WriteString(w, "the same stable response body for every request method")
	}))
	defer srv.Close()

	baseline := &methodProbeBaseline{
		status: http.StatusOK,
		body:   []byte("the same stable response body for every request method"),
	}
	got := probeURLMethodsWithBaseline(nil, srv.URL, []string{"GET", "POST"}, "", baseline)
	if strings.Join(got, ",") != "GET" {
		t.Fatalf("worked methods = %v, want GET", got)
	}
	if getHits != 0 {
		t.Fatalf("GET was fetched %d time(s), want 0 because the page response is the baseline", getHits)
	}
	if postHits != 1 {
		t.Fatalf("POST was fetched %d time(s), want 1", postHits)
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
		// per-method calibration has a catch-all to learn. POST returns a distinctly
		// larger body than GET so the two are distinguishable by the coarse response
		// signature (a POST that merely echoed the GET body would read as the server
		// ignoring the method and be collapsed).
		if r.URL.Path == "/api/submit" {
			if r.Method == "POST" {
				io.WriteString(w, `<html><body>submission accepted and stored with a confirmation identifier and many more descriptive words here</body></html>`)
				return
			}
			io.WriteString(w, `<html><body>submit</body></html>`)
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

// Gathered URL probing must use controls with the candidate's own path shape.
// Framework routers can serve extensionless random paths as valid dynamic pages
// while returning a distinct HTTP-200 not-found shell for every .js path.
func TestProbeURLMethodsRejectsShapeSpecificSoft404(t *testing.T) {
	const (
		dynamicPage = "submit a new issue through this valid dynamic application route"
		jsSoft404   = "page not found for this static-looking javascript resource"
		realBundle  = "export const applicationBundle = true with several unique words"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/new/real.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, realBundle)
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, jsSoft404)
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, dynamicPage)
		}
	}))
	defer srv.Close()

	cal := newAutoCalibrator()
	cal.setBase(srv.URL)
	if got := probeURLMethods(cal, srv.URL+"/new/firebase-messaging-sw.js", []string{"GET"}, ""); len(got) != 0 {
		t.Fatalf("shape-specific soft-404 reported as gathered methods: %v", got)
	}
	if got := probeURLMethods(cal, srv.URL+"/new/real.js", []string{"GET"}, ""); !equalStrings(got, []string{"GET"}) {
		t.Fatalf("real bundle sharing the calibrated .js level was suppressed: %v", got)
	}
}

// TestProbeURLMethodsCollapsesMethodAgnostic verifies the GET-baseline collapse:
// a resource that answers every verb with the same response (a CDN/static server
// ignoring the method) is reported as GET only, while a real POST-only endpoint
// that rejects GET still reports POST.
func TestProbeURLMethodsCollapsesMethodAgnostic(t *testing.T) {
	mux := http.NewServeMux()
	// Method-agnostic: identical 200 body for every verb, like a static file served
	// by an edge that ignores the request method.
	mux.HandleFunc("/asset.js", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "export const x = 1; // identical bytes returned for every method here")
	})
	// Real POST-only endpoint: GET (and the other verbs) are rejected with 405.
	mux.HandleFunc("/api/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			io.WriteString(w, "created a brand new record with several distinct words in the body")
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, "method not allowed")
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	methods := defaultRequestMethods()

	if got := probeURLMethods(nil, ts.URL+"/asset.js", methods, ""); !equalStrings(got, []string{"GET"}) {
		t.Fatalf("method-agnostic resource should collapse to GET only, got %v", got)
	}
	if got := probeURLMethods(nil, ts.URL+"/api/create", methods, ""); !equalStrings(got, []string{"POST"}) {
		t.Fatalf("POST-only endpoint should report POST only, got %v", got)
	}
}

func TestParamReplayChanged(t *testing.T) {
	if paramReplayChanged(200, []byte("same body here"), 200, []byte("same body here")) {
		t.Fatal("identical responses must not count as changed")
	}
	if !paramReplayChanged(302, nil, 400, nil) {
		t.Fatal("a different status must count as changed")
	}
	if !paramReplayChanged(200, []byte("one two three four five six"), 200, []byte("one")) {
		t.Fatal("a different word count must count as changed")
	}
}

// TestProbeParamReplayMethodsRequiresEffect verifies the differential check: a
// replayed body is attributed to an endpoint only when it changes that endpoint's
// response versus its own empty-body baseline, and only ever for body-bearing
// verbs. An SSR-style endpoint that echoes the same shell regardless of input is
// dropped, which is what stops login params from being reported against every
// crawled level.
func TestProbeParamReplayMethodsRequiresEffect(t *testing.T) {
	mux := http.NewServeMux()
	// /consumes reflects the request body, so a body-bearing request differs from
	// the empty-body baseline: the params genuinely worked here.
	mux.HandleFunc("/consumes", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			io.WriteString(w, "accepted "+string(b)+" with several extra words that shift the signature")
			return
		}
		io.WriteString(w, "empty")
	})
	// /ignores answers with an identical soft-200 no matter what body it is sent,
	// like a catch-all SSR shell: the params did not work here and must be dropped.
	mux.HandleFunc("/ignores", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "always the same shell response body regardless of any input")
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	methods := defaultRequestMethods()
	body := "username=testuser&password=Password123!"

	got := probeParamReplayMethods(nil, ts.URL+"/consumes", methods, body)
	if !equalStrings(got, []string{"POST", "PUT", "PATCH"}) {
		t.Fatalf("endpoint that consumes the body should report only body verbs, got %v", got)
	}

	if got := probeParamReplayMethods(nil, ts.URL+"/ignores", methods, body); len(got) != 0 {
		t.Fatalf("endpoint that ignores the body should report nothing, got %v", got)
	}

	if got := probeParamReplayMethods(nil, ts.URL+"/consumes", methods, ""); got != nil {
		t.Fatalf("empty params must not probe at all, got %v", got)
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
