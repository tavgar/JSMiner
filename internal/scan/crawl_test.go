package scan

import (
	"fmt"
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

// TestCrawlTargetsResolveAgainstSource verifies that a relative path lifted from
// a cross-origin script resolves to that script's host — landing off-scope and
// being dropped — rather than being misattributed to the seed host. A relative
// value from an inline (non-URL) source still resolves against the page.
func TestCrawlTargetsResolveAgainstSource(t *testing.T) {
	page := "https://teenused.telia.ee/"
	ms := []Match{
		// Found inside a third-party consent script: /settings.json is Cookiebot's,
		// not the seed host's, so it must not become teenused.telia.ee/settings.json.
		{Source: "https://consent.cookiebot.com/uc.js", Pattern: "endpoint_path", Value: "/settings.json"},
		// A relative path from an inline script shares the page's origin.
		{Source: "inline.js", Pattern: "endpoint_path", Value: "/real/page"},
	}

	got := crawlTargetsFromMatches(ms, page, "teenused.telia.ee", CrawlOptions{SameScopeOnly: true})

	if contains(got, "https://teenused.telia.ee/settings.json") {
		t.Fatalf("cross-origin relative path was misattributed to the seed host: %v", got)
	}
	if !contains(got, "https://teenused.telia.ee/real/page") {
		t.Fatalf("inline-source relative path should resolve against the page: %v", got)
	}
}

// TestScanURLCrawlCrossOriginRelativePath verifies the crawl does not misresolve
// a relative path found inside a cross-origin script against the seed host. The
// seed (127.0.0.1) loads a third-party script served under a different host
// (localhost) that references /settings.json; that path belongs to the
// third-party origin, so it must be scope-filtered out rather than turned into a
// bogus seed-host target — while a same-origin path (/dashboard) is still
// followed, proving the change does not over-filter genuine targets.
func TestScanURLCrawlCrossOriginRelativePath(t *testing.T) {
	// Third-party origin: its script points at its own /config.js.
	crossMux := http.NewServeMux()
	crossMux.HandleFunc("/uc.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/config.js');`)
	})
	tsCross := httptest.NewServer(crossMux)
	defer tsCross.Close()
	// Reference the third-party server by a hostname distinct from the seed's so
	// it is genuinely cross-origin (both bind 127.0.0.1; localhost resolves there).
	crossHost := strings.Replace(tsCross.URL, "127.0.0.1", "localhost", 1)

	const sameOriginSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3ZjNhOWM1In0.dQw4w9WgXcQ7kHl2mNpZ8rT"
	const crossOriginSecret = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiazlxUDFyVCJ9.aB3kLmZ9qP1rTuVwX2cY7nH"

	seedMux := http.NewServeMux()
	seedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><script src="/app.js"></script><script src="%s/uc.js"></script></html>`, crossHost)
	})
	// Same-origin path the crawl SHOULD follow.
	seedMux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/dashboard.js');`)
	})
	seedMux.HandleFunc("/dashboard.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `const a='%s';`, sameOriginSecret)
	})
	// The seed also happens to expose /config.js. If the cross-origin path were
	// misattributed to the seed host, the crawl would fetch this and leak the
	// secret — exactly the false-positive target the fix prevents. It is reachable
	// only via that misresolution; nothing on the seed links it.
	seedMux.HandleFunc("/config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `const b='%s';`, crossOriginSecret)
	})
	tsSeed := httptest.NewServer(seedMux)
	defer tsSeed.Close()

	e := NewExtractor(true, false)
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false
	// external=true so the cross-origin third-party script is scanned, as it is
	// against a real site (the seed's uc.js is off the seed host).
	matches, err := e.ScanURLCrawl(tsSeed.URL, false, true, false, opts)
	if err != nil {
		t.Fatal(err)
	}

	valueSeen := func(want string) bool {
		for _, m := range matches {
			if strings.Contains(m.Value, want) {
				return true
			}
		}
		return false
	}

	// Guard: only meaningful if the third-party script was actually reachable and
	// scanned (localhost resolved to the test server). Otherwise the cross-origin
	// scenario never ran, so skip rather than pass for the wrong reason.
	if !valueSeen("/config.js") {
		t.Skip("third-party script not scanned (localhost unresolved); scenario not exercised")
	}
	if !valueSeen(sameOriginSecret) {
		t.Fatalf("same-origin /dashboard.js secret should be reached via crawl; over-filtered")
	}
	if valueSeen(crossOriginSecret) {
		t.Fatalf("cross-origin /config.js was misresolved to the seed host and crawled")
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

// TestScanURLCrawlTemplateDedupURL verifies that templated URLs discovered on
// the seed — /product/1 … /product/N, which differ only in an id — are
// recognised as one class and only a representative few are fetched, so the
// crawl never spends its budget on the whole family. Disabling template dedup
// fetches every instance.
func TestScanURLCrawlTemplateDedupURL(t *testing.T) {
	var products productCounter
	mux := http.NewServeMux()
	// Seed links 40 product pages via inline fetch() calls (harvested as endpoints).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			var b strings.Builder
			b.WriteString(`<html><script>`)
			for i := 1; i <= 40; i++ {
				fmt.Fprintf(&b, "fetch('/product/%d');", i)
			}
			b.WriteString(`</script></html>`)
			io.WriteString(w, b.String())
			return
		}
		io.WriteString(w, `<html><body>short</body></html>`)
	})
	mux.HandleFunc("/product/", func(w http.ResponseWriter, r *http.Request) {
		products.hit(r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body><h1>a product</h1><p>details</p></body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	// Template dedup on: only TemplateSampleMax product instances are fetched.
	// Auto-calibration/method probing are off to isolate the URL-template classer.
	opts := CrawlOptions{MaxDepth: 2, SameScopeOnly: true, TemplateDedup: true, TemplateSampleMax: 3}
	if _, err := e.ScanURLCrawl(ts.URL+"/", true, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if got := products.count(); got != 3 {
		t.Fatalf("template dedup should fetch only 3 product instances, fetched %d", got)
	}

	// Template dedup off: every distinct product URL is fetched.
	products.reset()
	opts.TemplateDedup = false
	if _, err := e.ScanURLCrawl(ts.URL+"/", true, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if got := products.count(); got != 40 {
		t.Fatalf("without template dedup all 40 products should be fetched, fetched %d", got)
	}
}

// TestScanURLCrawlTemplateDedupStructural verifies the post-fetch layer: pages
// whose URLs give no hint they are templated (distinct slugs) but which share a
// structure and differ only in data are collapsed by the structural body
// signature, so only a representative few of their secrets are reported.
func TestScanURLCrawlTemplateDedupStructural(t *testing.T) {
	slugs := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"}
	// A distinct, valid-looking google_api key per slug page.
	keyFor := func(i int) string {
		body := "D1ad_UKyHFErfLeO_3aoBoNrX1W4bsm" // 31 chars
		return "AIza" + body + string(rune('a'+i)) + "xyz"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			var b strings.Builder
			b.WriteString(`<html><script>`)
			for _, s := range slugs {
				fmt.Fprintf(&b, "fetch('/%s');", s)
			}
			b.WriteString(`</script></html>`)
			io.WriteString(w, b.String())
		default:
			// A slug page: identical structure, data (the key) differs per slug.
			idx := slugIndex(slugs, strings.TrimPrefix(r.URL.Path, "/"))
			if idx < 0 {
				// Unknown paths (including calibration probes) get a short 404 shell
				// whose coarse shape (one word, one line) differs from the slug pages
				// so the wildcard filter cannot be what suppresses them.
				io.WriteString(w, `notfound`)
				return
			}
			// Every slug page shares this multi-line, multi-word layout; only the
			// embedded key differs, so structural dedup — not the coarse signature —
			// must be what collapses them.
			fmt.Fprintf(w, "<html>\n<body>\n<h1>the item title</h1>\n"+
				"<p>a paragraph of description text goes here</p>\n"+
				"<script>var k = \"%s\";</script>\n</body>\n</html>\n", keyFor(idx))
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	opts := CrawlOptions{MaxDepth: 2, SameScopeOnly: true, AutoCalibrate: true,
		TemplateDedup: true, TemplateSampleMax: 3}
	matches, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]struct{})
	for _, m := range matches {
		if m.Pattern == "google_api" {
			keys[m.Value] = struct{}{}
		}
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one product secret to be reported")
	}
	if len(keys) > 3 {
		t.Fatalf("structural dedup should keep at most 3 representatives, got %d distinct secrets", len(keys))
	}
}

// slugIndex returns the position of name in slugs, or -1.
func slugIndex(slugs []string, name string) int {
	for i, s := range slugs {
		if s == name {
			return i
		}
	}
	return -1
}

// productCounter counts fetches of numeric /product/<id> paths, ignoring
// calibration probes that hit the same handler with non-numeric tokens.
type productCounter struct {
	mu sync.Mutex
	n  int
}

func (c *productCounter) hit(path string) {
	last := path[strings.LastIndex(path, "/")+1:]
	if last == "" {
		return
	}
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return
		}
	}
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *productCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *productCounter) reset() {
	c.mu.Lock()
	c.n = 0
	c.mu.Unlock()
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

// TestScanURLPostsCrawlFollowsHTMLLinks verifies a posts crawl follows the HTML
// link graph — not just JavaScript references — to reach a POST endpoint that is
// only discoverable by navigating to a deeper page, and that the navigation-only
// markup links do not leak into the POST-filtered output.
func TestScanURLPostsCrawlFollowsHTMLLinks(t *testing.T) {
	mux := http.NewServeMux()
	// Seed page: a plain HTML link to /deep and no script of its own.
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body><a href="/deep">deep</a></body></html>`)
	})
	// Deep page: reachable only via the seed's HTML link; loads a bundle.
	mux.HandleFunc("/deep", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body><script src="/d.js"></script></body></html>`)
	})
	mux.HandleFunc("/d.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/api/submit',{method:'POST',body:JSON.stringify({x:1})});`)
	})
	mux.HandleFunc("/api/submit", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	opts := CrawlOptions{MaxDepth: 3, MaxPages: 30, SameScopeOnly: true, AutoCalibrate: true}
	ms, err := e.ScanURLPostsCrawl(ts.URL+"/", false, false, opts)
	if err != nil {
		t.Fatalf("posts crawl error: %v", err)
	}

	foundPost := false
	for _, m := range ms {
		if (m.Pattern == "post_url" || m.Pattern == "post_path") && strings.HasSuffix(m.Value, "/api/submit") {
			foundPost = true
		}
	}
	if !foundPost {
		t.Errorf("posts crawl did not reach /api/submit via the HTML link graph; matches=%v", ms)
	}

	// After POST filtering, only post/gathered patterns remain — no endpoint_url
	// navigation links.
	for _, m := range FilterPostMatches(ms) {
		if strings.HasPrefix(m.Pattern, "endpoint_") {
			t.Errorf("navigation link leaked into POST output: %+v", m)
		}
	}
}
