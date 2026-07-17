package scan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// statusRecorder wraps a ResponseWriter to capture the status code the handler
// wrote, so a test can categorise responses.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// probeCountServer serves a small, realistic API — a handful of GET endpoints
// under several directory levels — and 404s every other path, so a crawl's
// auto-calibration probes (which hit random, non-existent paths) show up cleanly
// as 404s and can be told apart from real-endpoint traffic. Non-GET verbs on a
// GET-only endpoint answer 405, mirroring a typical REST service. It records a
// per-(method,status) tally so a crawl's request budget can be measured.
type probeCountServer struct {
	*httptest.Server
	mu    sync.Mutex
	tally map[string]int // key: METHOD|status
	total int
}

func newProbeCountServer() *probeCountServer {
	s := &probeCountServer{tally: map[string]int{}}
	mux := http.NewServeMux()

	// Seed page links every endpoint as a rooted path, so static scanning (no
	// render) discovers them all without a browser.
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body>
<a href="/api/v1/users">u</a><a href="/api/v1/orders">o</a>
<a href="/api/v2/products">p</a><a href="/api/v2/reviews">r</a>
<a href="/data/report">d</a>
</body></html>`)
	})

	endpoints := []string{"/api/v1/users", "/api/v1/orders", "/api/v2/products", "/api/v2/reviews", "/data/report"}
	for _, p := range endpoints {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		})
	}

	s.Server = httptest.NewServer(s.record(mux))
	return s
}

func (s *probeCountServer) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.mu.Lock()
		s.tally[fmt.Sprintf("%s|%d", r.Method, rec.status)]++
		s.total++
		s.mu.Unlock()
	})
}

func (s *probeCountServer) snapshot() (map[string]int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.tally))
	for k, v := range s.tally {
		out[k] = v
	}
	return out, s.total
}

// TestCrawlProbeBudget measures how a default crawl spends its requests against a
// fixed 5-endpoint API (render off, so only the Go probing path is exercised). It
// prints a per-(method,status) breakdown and asserts loose ceilings, so a future
// change that multiplies the crawl's request count — the thing that trips rate
// limits — fails here instead of in the field. It uses no browser and is
// deterministic, so it runs in the normal suite.
func TestCrawlProbeBudget(t *testing.T) {
	srv := newProbeCountServer()
	defer srv.Close()
	ResetThrottle()

	e := NewExtractor(false, false)
	opts := DefaultCrawlOptions()
	opts.MaxDepth = 2
	opts.MaxPages = 40

	matches, err := e.ScanURLCrawl(srv.URL, false, false /*external*/, false /*render*/, opts)
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	tally, total := srv.snapshot()
	t.Logf("crawl issued %d requests against 5 endpoints; breakdown by method|status: %v", total, tally)

	// All five endpoints must be confirmed as gathered URLs (GET works on each).
	gathered := 0
	for _, m := range matches {
		if m.Pattern == GatheredURLPattern {
			gathered++
		}
	}
	if gathered < 5 {
		t.Errorf("expected >=5 gathered URLs (one per endpoint), got %d", gathered)
	}

	// Ceiling guard: with 5 endpoints + seed and six probed methods plus
	// calibration, a default crawl should stay well under this. If it doesn't, the
	// probing amplification has regressed.
	const ceiling = 200
	if total > ceiling {
		t.Errorf("probe budget regression: %d requests for 5 endpoints exceeds ceiling %d (breakdown %v)", total, ceiling, tally)
	}
}

func TestCrawlDoesNotProbeSkippedDuplicatePage(t *testing.T) {
	var mu sync.Mutex
	postHits := map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			postHits[r.URL.Path]++
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/a">a</a><a href="/b">b</a></body></html>`)
		case "/a", "/b":
			fmt.Fprint(w, `<html><body>identical duplicate page body with a deliberately distinct and much longer response shape for calibration accuracy</body></html>`)
		default:
			fmt.Fprint(w, `<html><body>calibration catch all page</body></html>`)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := NewExtractor(false, false)
	opts := CrawlOptions{
		MaxDepth: 1, MaxPages: 3, SameScopeOnly: true,
		AutoCalibrate: true, ProbeMethods: true,
		RequestMethods: []string{"GET", "POST"}, Concurrency: 1,
	}
	if _, err := e.ScanURLCrawl(srv.URL, false, false, false, opts); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := postHits["/a"] + postHits["/b"]
	mu.Unlock()
	if got != 1 {
		t.Fatalf("duplicate pages received %d POST probes, want 1 (the accepted representative only)", got)
	}
}
