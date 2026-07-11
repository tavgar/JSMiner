package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// TestScanURLCrawl verifies that the crawler follows an in-scope endpoint path
// discovered on the seed page to reach a JS file that is not linked from the
// seed, surfacing a secret that a plain ScanURL would miss.
func TestScanURLCrawl(t *testing.T) {
	mux := http.NewServeMux()
	// Seed page: links a script that only reveals a same-host API path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/app.js"></script></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/dashboard');`)
	})
	// The crawled path is an HTML page linking a second, otherwise-unreferenced
	// bundle that holds the secret.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/secret.js"></script></html>`)
	})
	mux.HandleFunc("/secret.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const t='eyJabc.def.ghi';`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	// Without crawling the JWT behind /dashboard is unreachable.
	plain, err := e.ScanURL(ts.URL, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(plain, "jwt") {
		t.Fatal("did not expect jwt without crawling")
	}

	// This test isolates crawl reachability; auto-calibration is exercised
	// separately (calibrate_test.go). The toy pages here are near-identical in
	// shape, so the coarse wildcard signature would collapse them — disable it.
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false
	matches, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "jwt") {
		t.Fatalf("expected jwt reached via crawl, got %+v", matches)
	}
}

// TestScanURLCrawlDepth verifies that the depth budget bounds how far the crawl
// follows a chain of linked pages: depth 0 scans only the seed, while a deeper
// budget reaches a secret several hops away.
func TestScanURLCrawlDepth(t *testing.T) {
	// /p0 -> /p1 -> /p2 (holds the jwt), each an HTML page whose inline script
	// links the next hop. Inline scripts are parsed for endpoints, so this
	// exercises the real reachable crawl path.
	mux := http.NewServeMux()
	page := func(next, extra string) string {
		return `<html><script>fetch('` + next + `');` + extra + `</script></html>`
	}
	mux.HandleFunc("/p0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, page("/p1", ""))
	})
	mux.HandleFunc("/p1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, page("/p2", ""))
	})
	mux.HandleFunc("/p2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, page("/p3", `const t='eyJabc.def.ghi';`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	shallow, err := e.ScanURLCrawl(ts.URL+"/p0", false, false, false, CrawlOptions{MaxDepth: 0, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(shallow, "jwt") {
		t.Fatal("depth 0 should not reach the jwt two hops away")
	}

	deep, err := e.ScanURLCrawl(ts.URL+"/p0", false, false, false, CrawlOptions{MaxDepth: 2, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(deep, "jwt") {
		t.Fatalf("depth 2 should reach the jwt, got %+v", deep)
	}
}

// TestScanURLCrawlUnlimitedDepth verifies that a negative MaxDepth follows a
// chain deeper than any fixed budget, reaching a secret four hops from the seed
// that a bounded crawl at the default depth cannot.
func TestScanURLCrawlUnlimitedDepth(t *testing.T) {
	// /p0 -> /p1 -> /p2 -> /p3 -> /p4 (holds the jwt), each linking the next hop.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		extra := ""
		if r.URL.Path == "/p4" {
			extra = `const t='eyJabc.def.ghi';`
		}
		io.WriteString(w, `<html><script>fetch('`+nextHop(r.URL.Path)+`');`+extra+`</script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	// The default depth (2) stops well short of /p4.
	bounded, err := e.ScanURLCrawl(ts.URL+"/p0", false, false, false, CrawlOptions{MaxDepth: 2, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(bounded, "jwt") {
		t.Fatal("depth 2 should not reach the jwt four hops away")
	}

	// Unlimited depth (negative) follows the whole chain.
	unlimited, err := e.ScanURLCrawl(ts.URL+"/p0", false, false, false, CrawlOptions{MaxDepth: -1, SameScopeOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(unlimited, "jwt") {
		t.Fatalf("unlimited depth should reach the jwt, got %+v", unlimited)
	}
}

// nextHop maps /pN to /p(N+1) for the depth-chain test server.
func nextHop(path string) string {
	switch path {
	case "/p0":
		return "/p1"
	case "/p1":
		return "/p2"
	case "/p2":
		return "/p3"
	case "/p3":
		return "/p4"
	default:
		return "/end"
	}
}

// TestCrawlTargetsFromMatches unit-tests scope and asset filtering of the
// next-hop selection, independent of the network (httptest shares 127.0.0.1 so
// scope cannot be exercised with distinct real hosts otherwise).
func TestCrawlTargetsFromMatches(t *testing.T) {
	ms := []Match{
		{Pattern: "endpoint_path", Value: "/in/scope"},
		{Pattern: "endpoint_url", Value: "https://sub.example.com/also"},
		{Pattern: "endpoint_url", Value: "https://evil.com/nope"},
		{Pattern: "endpoint_path", Value: "/logo.png"},
		{Pattern: "google_api", Value: "AIzaSyD1ad_UKyHFErfLeO_3aoBoNrX1W4bsmac"},
		// A genuine `path` finding (with the rule's stray leading space) is a
		// crawl target too; a Windows path is not a web URL and must fall out.
		{Pattern: "path", Value: " /admin/panel"},
		{Pattern: "path", Value: `C:\Windows\System32`},
	}
	page := "https://example.com/page"

	scoped := crawlTargetsFromMatches(ms, page, "example.com", CrawlOptions{SameScopeOnly: true})
	want := []string{
		"https://example.com/in/scope",
		"https://sub.example.com/also",
		"https://example.com/admin/panel",
	}
	if !equalStrings(scoped, want) {
		t.Fatalf("same-scope targets = %v, want %v", scoped, want)
	}

	all := crawlTargetsFromMatches(ms, page, "example.com", CrawlOptions{SameScopeOnly: false})
	if !contains(all, "https://evil.com/nope") {
		t.Fatalf("off-scope target should be included when SameScopeOnly=false: %v", all)
	}
	if contains(all, "https://example.com/logo.png") {
		t.Fatalf("binary asset should never be a crawl target: %v", all)
	}
	for _, tgt := range all {
		if strings.HasPrefix(tgt, "c:") || strings.Contains(tgt, "Windows") {
			t.Fatalf("windows path leaked into crawl targets: %v", all)
		}
	}
}

// TestScanURLCrawlMaxPages ensures the page budget halts the crawl even when the
// link graph is effectively unbounded.
func TestScanURLCrawlMaxPages(t *testing.T) {
	var mu chanCounter
	mux := http.NewServeMux()
	// Every /pN page links /pNx, forming an unbounded chain of distinct paths.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.inc()
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script>fetch('`+r.URL.Path+`x');</script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	opts := CrawlOptions{MaxDepth: 100, MaxPages: 3, SameScopeOnly: true}
	if _, err := e.ScanURLCrawl(ts.URL+"/p", true, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if got := mu.count(); got != 3 {
		t.Fatalf("expected exactly 3 fetches under page cap, got %d", got)
	}
}

func TestCrawlableTarget(t *testing.T) {
	cases := map[string]bool{
		"https://x.com/app.js":     true,
		"https://x.com/api/data":   true,
		"https://x.com/route":      true,
		"https://x.com/logo.png":   false,
		"https://x.com/font.woff2": false,
		"https://x.com/clip.mp4":   false,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := crawlableTarget(u); got != want {
			t.Errorf("crawlableTarget(%s)=%v want %v", raw, got, want)
		}
	}
}

func hasPattern(ms []Match, pat string) bool {
	for _, m := range ms {
		if m.Pattern == pat {
			return true
		}
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// chanCounter is a tiny concurrency-safe counter for the page-cap test.
type chanCounter struct {
	mu sync.Mutex
	n  int
}

func (c *chanCounter) inc() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *chanCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
