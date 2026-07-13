package scan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCrawlLiveComplexSPA drives the real crawler against a local, JS-heavy
// single-page app that plants endpoints in every shape the extractor is meant to
// find — rooted string paths, template literals, bare relative fetch() paths,
// runtime-only XHR URLs, client-side route links and a form POST — and layers a
// rate limiter on top so the adaptive throttle is exercised end-to-end.
//
// It needs a real headless Chrome and takes tens of seconds, so it is gated
// behind JSMINER_LIVE=1 and skipped when no Chrome binary is on PATH; the rest of
// the suite (and CI) is unaffected. Run it with:
//
//	JSMINER_LIVE=1 go test ./internal/scan/ -run TestCrawlLiveComplexSPA -v
func TestCrawlLiveComplexSPA(t *testing.T) {
	if os.Getenv("JSMINER_LIVE") != "1" {
		t.Skip("live crawl test: set JSMINER_LIVE=1 to run")
	}
	if !chromeAvailable() {
		t.Skip("live crawl test: no Chrome/Chromium binary found on PATH")
	}

	srv := newComplexSPAServer()
	defer srv.Close()

	// Keep the render fast and bounded for a test while still exploring state.
	restore := tuneForLiveTest()
	defer restore()
	ResetThrottle()

	// Use whatever browser is already available (cache/PATH) without a network
	// version lookup or download, so the crawl test stays hermetic.
	savedAuto := AutoDownloadBrowser
	AutoDownloadBrowser = false
	resetResolvedBrowser()
	defer func() { AutoDownloadBrowser = savedAuto; resetResolvedBrowser() }()

	e := NewExtractor(false, false)
	opts := DefaultCrawlOptions()
	opts.MaxDepth = 3
	opts.MaxPages = 40

	matches, err := e.ScanURLCrawl(srv.URL, false, true, true, opts)
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	found := collectEndpointValues(matches)
	t.Logf("discovered %d endpoint/gathered values:\n%s", len(found), strings.Join(sortedKeys(found), "\n"))

	// Item #2: the crawler must surface each planted URL shape. Values are matched
	// by substring so query strings and trailing segments don't cause misses.
	wantContains := map[string]string{
		"rooted string path":        "/api/v1/users",
		"nested rooted path":        "/api/v1/orders/history",
		"template-literal base":     "/api/user/",
		"bare relative fetch path":  "api/search",
		"runtime-only XHR endpoint": "/api/runtime/telemetry",
		"route-link API call":       "/api/dashboard/widgets",
		"form POST endpoint":        "/api/login",
		"sitemap-only endpoint":     "/api/hidden/report",
		"robots.txt directory":      "/admin/private",
	}
	for label, want := range wantContains {
		if !anyContains(found, want) {
			t.Errorf("item #2 gap: crawler did not discover %s (%q)", label, want)
		}
	}

	// Item #3: every 429 the server issued must have been followed by a real
	// pause before the next request, proving the throttle honoured Retry-After
	// against the live crawl rather than hammering through the limit.
	srv.assertBackoffHonoured(t, 900*time.Millisecond)
	goReqs := srv.goRequests()
	t.Logf("server saw %d requests (%d via throttled Go client, %d via headless Chrome), issued %d 429s",
		srv.total(), goReqs, srv.total()-goReqs, srv.throttled())
}

// tuneForLiveTest shortens the render waits so the live test finishes quickly,
// returning a function that restores the previous values.
func tuneForLiveTest() func() {
	savedSleep, savedTimeout, savedSettle, savedStates := RenderSleepDuration, RenderTimeout, ExploreSettleDuration, MaxExploreStates
	RenderSleepDuration = 700 * time.Millisecond
	RenderTimeout = 12 * time.Second
	ExploreSettleDuration = 500 * time.Millisecond
	MaxExploreStates = 8
	return func() {
		RenderSleepDuration, RenderTimeout, ExploreSettleDuration, MaxExploreStates = savedSleep, savedTimeout, savedSettle, savedStates
	}
}

func chromeAvailable() bool {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "headless_shell"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// complexSPAServer is a local app that plants endpoints in many shapes and rate
// limits its own API so the crawler's discovery and throttle are both exercised.
type complexSPAServer struct {
	*httptest.Server

	mu        sync.Mutex
	stamps    []time.Time // arrival time of every request
	is429     []bool      // whether each request was answered with 429
	fromGo    []bool      // whether each request came from the throttled Go client
	windowN   int         // requests seen in the current limiter window
	windowEnd time.Time
	n429      int
}

// isBrowserRequest reports whether r was issued by headless Chrome rather than
// the throttled Go HTTP client. Chrome always sends Sec-Fetch-* (and, on modern
// builds, sec-ch-ua) request headers; the Go client sends neither. Only the Go
// path flows through globalThrottle, so backoff can only be asserted on it.
func isBrowserRequest(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") != "" || r.Header.Get("Sec-Fetch-Dest") != "" || r.Header.Get("Sec-Ch-Ua") != ""
}

func newComplexSPAServer() *complexSPAServer {
	s := &complexSPAServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimited(w, r) {
			return
		}
		// The SPA shell: an app div, a bundle, and a client-side route link that
		// serves the same shell (so the crawl dedups it and only the in-place route
		// render reaches /api/dashboard/widgets).
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><head><title>App</title></head><body>
<div id="app">loading</div>
<nav><a href="/dashboard">Dashboard</a> <a href="/settings">Settings</a></nav>
<form id="login" action="/api/login" method="post">
  <input type="email" name="email"><input type="password" name="password">
  <button type="submit">Sign in</button>
</form>
<script src="/static/app.js"></script>
<script>
  // Runtime-only endpoint: built at run time, present in no shipped string.
  var region = "eu";
  fetch("/api/runtime/telemetry?region=" + region);
  // Client-side router: renders route content in place and calls a per-route API.
  function route() {
    var p = location.pathname;
    if (p === "/dashboard") { fetch("/api/dashboard/widgets"); document.getElementById("app").innerHTML = "dashboard"; }
    else { document.getElementById("app").innerHTML = "home"; }
  }
  window.addEventListener("popstate", route);
  document.querySelectorAll("nav a").forEach(function(a){
    a.addEventListener("click", function(ev){ ev.preventDefault(); history.pushState({}, "", a.getAttribute("href")); route(); });
  });
  route();
</script>
</body></html>`)
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimited(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		// A bundle exercising many endpoint shapes at once.
		fmt.Fprint(w, `
			const API = "/api/v1";
			export function loadUsers(){ return fetch("/api/v1/users").then(r=>r.json()); }
			export function history(){ return fetch("/api/v1/orders/history"); }
			export function profile(id){ return fetch(`+"`/api/user/${id}/profile`"+`); }
			export function search(q){ return fetch("api/search?q=" + q); }
			const socket = new WebSocket("wss://example-internal.test/live");
			const doc = "https://reactjs.org/docs"; // library noise, must be dropped
			axios.post("/api/v1/orders", {sku: 1});
		`)
	})

	// robots.txt and a sitemap expose a path that no page or bundle references, so
	// it is reachable only through well-known discovery.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nDisallow: /admin/private\nSitemap: %s/sitemap.xml\n", s.URL)
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<urlset><url><loc>%s/api/hidden/report</loc></url></urlset>`, s.URL)
	})

	// API endpoints. They 200 so method probing sees them as live; the limiter can
	// still 429 any of them under burst.
	for _, p := range []string{"/api/v1/users", "/api/v1/orders/history", "/api/v1/orders",
		"/api/runtime/telemetry", "/api/dashboard/widgets", "/api/login", "/api/search",
		"/api/hidden/report", "/admin/private"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if s.rateLimited(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		})
	}

	s.Server = httptest.NewServer(mux)
	return s
}

// rateLimited records the request and, when the current burst window is over
// budget, answers 429 with Retry-After. It returns true when it has written the
// 429 response so the handler should stop.
func (s *complexSPAServer) rateLimited(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	now := time.Now()
	if now.After(s.windowEnd) {
		s.windowEnd = now.Add(1 * time.Second)
		s.windowN = 0
	}
	s.windowN++
	limited := s.windowN > 6
	s.stamps = append(s.stamps, now)
	s.is429 = append(s.is429, limited)
	s.fromGo = append(s.fromGo, !isBrowserRequest(r))
	if limited {
		s.n429++
	}
	s.mu.Unlock()

	if limited {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}
	return false
}

func (s *complexSPAServer) total() int     { s.mu.Lock(); defer s.mu.Unlock(); return len(s.stamps) }
func (s *complexSPAServer) throttled() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n429 }
func (s *complexSPAServer) goRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, g := range s.fromGo {
		if g {
			n++
		}
	}
	return n
}

// assertBackoffHonoured checks that after any 429 answered to the throttled Go
// client, the client's *next* request arrived at least minGap later — i.e. the
// throttle honoured Retry-After instead of hammering through the limit. Only the
// Go path flows through globalThrottle, so headless-Chrome's own render requests
// (which the throttle does not govern) are excluded from the sequence.
func (s *complexSPAServer) assertBackoffHonoured(t *testing.T, minGap time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Project the request log down to just the throttled Go client, preserving order.
	var goStamps []time.Time
	var go429 []bool
	goThrottled := 0
	for i := range s.stamps {
		if !s.fromGo[i] {
			continue
		}
		goStamps = append(goStamps, s.stamps[i])
		go429 = append(go429, s.is429[i])
		if s.is429[i] {
			goThrottled++
		}
	}

	checked := 0
	for i := 0; i < len(goStamps)-1; i++ {
		if !go429[i] {
			continue
		}
		gap := goStamps[i+1].Sub(goStamps[i])
		checked++
		if gap < minGap {
			t.Errorf("item #3 gap: Go request after a 429 came only %s later (want >= %s)", gap.Round(time.Millisecond), minGap)
		}
	}
	if goThrottled > 0 && checked == 0 {
		t.Errorf("item #3: server issued %d 429s to the Go client but none had a following request to verify backoff", goThrottled)
	}
	if goThrottled == 0 {
		t.Logf("item #3: no 429s reached the throttled Go client this run (browser requests dominated the burst)")
	}
}

func collectEndpointValues(ms []Match) map[string]struct{} {
	out := make(map[string]struct{})
	for _, m := range ms {
		switch m.Pattern {
		case "endpoint_url", "endpoint_path", "post_url", "post_path", GatheredURLPattern:
			out[strings.TrimSpace(m.Value)] = struct{}{}
		}
	}
	return out
}

func anyContains(set map[string]struct{}, sub string) bool {
	for v := range set {
		if strings.Contains(v, sub) {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// simple insertion sort to avoid importing sort in a test helper already heavy
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
