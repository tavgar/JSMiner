package scan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPassivePathCandidateRebasesPathAndDropsHistoricalQuery(t *testing.T) {
	seed, err := url.Parse("https://example.com:8443/start?current=1")
	if err != nil {
		t.Fatal(err)
	}

	got, ok := passivePathCandidate(seed, "http://example.com/api/a%2Fb/config.js?token=secret#old")
	if !ok {
		t.Fatal("valid archived path was rejected")
	}
	if want := "https://example.com:8443/api/a%2Fb/config.js"; got != want {
		t.Fatalf("rebased URL = %q, want %q", got, want)
	}

	rejected := []string{
		"https://www.example.com/admin",       // separate origin/application
		"https://evil.example/admin",          // off-scope
		"https://example.com/",                // duplicates the seed root
		"https://example.com/static/logo.png", // binary crawl target
		"https://example.com/a/%2e%2e/admin",  // decoded traversal segment
		"ftp://example.com/admin",             // non-web scheme
	}
	for _, raw := range rejected {
		if live, ok := passivePathCandidate(seed, raw); ok {
			t.Errorf("unsafe/noisy archived URL %q accepted as %q", raw, live)
		}
	}
}

func TestDiscoverPassiveURLsUsesProvidersWithoutLeakingTargetHeaders(t *testing.T) {
	oldWayback := waybackCDXEndpoint
	oldCollections := commonCrawlCollectionsURL
	oldHeaders := extraHeaders.Clone()
	defer func() {
		waybackCDXEndpoint = oldWayback
		commonCrawlCollectionsURL = oldCollections
		SetExtraHeaders(oldHeaders)
	}()

	SetExtraHeaders(http.Header{
		"Authorization": []string{"Bearer target-only-secret"},
		"Cookie":        []string{"session=target-only"},
	})

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("target credentials leaked to passive provider: headers=%v", r.Header)
		}
		switch r.URL.Path {
		case "/wayback":
			if got := r.URL.Query().Get("filter"); got != "statuscode:200" {
				t.Errorf("Wayback status filter = %q", got)
			}
			io.WriteString(w, `[
				["original"],
				["http://target.example/admin?session=archived"],
				["https://www.target.example/from-other-origin"],
				["https://target.example/image.png"]
			]`)
		case "/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":%q}]`, provider.URL+"/cc-index")
		case "/cc-index":
			if got := r.URL.Query().Get("filter"); got != "status:200" {
				t.Errorf("Common Crawl status filter = %q", got)
			}
			io.WriteString(w, "{\"url\":\"https://target.example/api/config.js?tracking=1\"}\n")
			io.WriteString(w, "{\"url\":\"https://target.example/admin?duplicate=1\"}\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	waybackCDXEndpoint = provider.URL + "/wayback"
	commonCrawlCollectionsURL = provider.URL + "/collinfo.json"

	seed, _ := url.Parse("https://target.example/")
	got := discoverPassiveURLs(seed, nil, 10)
	if len(got) != 2 {
		t.Fatalf("passive candidates = %+v, want two sanitized unique paths", got)
	}
	if got[0].URL != "https://target.example/api/config.js" ||
		got[0].Source != passiveSourceCommonCrawl {
		t.Fatalf("highest-yield candidate = %+v, want Common Crawl JS path", got[0])
	}
	if got[1].URL != "https://target.example/admin" ||
		got[1].Source != passiveSourceWayback {
		t.Fatalf("second candidate = %+v, want de-duplicated Wayback path", got[1])
	}
}

func TestPassiveProvidersAreQueriedConcurrently(t *testing.T) {
	oldWayback := waybackCDXEndpoint
	oldCollections := commonCrawlCollectionsURL
	defer func() {
		waybackCDXEndpoint = oldWayback
		commonCrawlCollectionsURL = oldCollections
	}()

	var active, maxActive atomic.Int32
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		active.Add(-1)

		switch r.URL.Path {
		case "/wayback":
			io.WriteString(w, `[["original"],["https://target.example/from-wayback.js"]]`)
		case "/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":%q}]`, provider.URL+"/cc-index")
		case "/cc-index":
			io.WriteString(w, `{"url":"https://target.example/from-commoncrawl.js"}`+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	waybackCDXEndpoint = provider.URL + "/wayback"
	commonCrawlCollectionsURL = provider.URL + "/collinfo.json"

	seed, _ := url.Parse("https://target.example/")
	got := discoverPassiveURLs(seed, nil, 10)
	if len(got) != 2 {
		t.Fatalf("passive candidates = %+v, want two", got)
	}
	if maxActive.Load() < 2 {
		t.Fatalf("passive provider requests did not overlap; max concurrency=%d", maxActive.Load())
	}
}

func TestPassiveSoft404IsRejectedBeforeScanning(t *testing.T) {
	const catchAll = "this route does not exist anywhere on this service"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, catchAll)
	}))
	defer srv.Close()

	cal := newAutoCalibrator()
	cal.setBase(srv.URL)
	e := NewExtractor(true, false)
	ms, accepted, err := e.scanURLValidated(
		srv.URL+"/ghost/dead.js", strings.TrimPrefix(srv.URL, "http://"),
		false, newVisitedSet(), false, false, cal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if accepted || len(ms) != 0 {
		t.Fatalf("soft-404 passive path accepted=%t matches=%v", accepted, ms)
	}
}

// A mixed level calibration used to miss this routing pattern: two random
// extensionless paths resolve to a real dynamic page, while the single random
// .js control and every historical .js candidate receive the same soft-404.
// Passive validation must run enough candidate-shaped controls to reject it.
func TestPassiveShapeSpecificSoft404IsRejected(t *testing.T) {
	const (
		dynamicPage = "submit a new issue through this valid dynamic application route"
		jsSoft404   = "page not found for this static-looking javascript resource"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(r.URL.Path, ".js") {
			io.WriteString(w, jsSoft404)
			return
		}
		io.WriteString(w, dynamicPage)
	}))
	defer srv.Close()

	cal := newAutoCalibrator()
	cal.setBase(srv.URL)
	e := NewExtractor(true, false)
	ms, accepted, err := e.scanURLValidated(
		srv.URL+"/new/firebase-messaging-sw.js", strings.TrimPrefix(srv.URL, "http://"),
		false, newVisitedSet(), false, false, cal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if accepted || len(ms) != 0 {
		t.Fatalf("shape-specific passive soft-404 accepted=%t matches=%v", accepted, ms)
	}
}

func TestPassiveValidatedPathFeedsPermuterButRejectedPathDoesNot(t *testing.T) {
	oldWayback := waybackCDXEndpoint
	defer func() { waybackCDXEndpoint = oldWayback }()

	const (
		secret      = "eyJhbGciOiJIUzI1NiJ9.eyJwYXNzaXZlIjoxfQ.passivePermutationSignature"
		staleSecret = "eyJhbGciOiJIUzI1NiJ9.eyJzdGFsZSI6MX0.staleResponseMustNotScan"
	)
	var (
		target                  *httptest.Server
		secretHits              atomic.Int32
		stalePermuteHits        atomic.Int32
		historicalQueryReplayed atomic.Bool
	)
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><script>fetch('/api/status')</script></html>`)
		case "/api/status":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":true}`)
		case "/legacy/admin/config.js":
			if r.URL.RawQuery != "" {
				historicalQueryReplayed.Store(true)
			}
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `const current=true;`)
		case "/stale/admin/config.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `const stale="`+staleSecret+`";`)
		case "/api/admin/config.js":
			secretHits.Add(1)
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `const token="`+secret+`";`)
		case "/api/stale/admin/config.js":
			stalePermuteHits.Add(1)
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	archive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[["original"],[%q],[%q]]`,
			target.URL+"/legacy/admin/config.js?token=historical",
			target.URL+"/stale/admin/config.js")
	}))
	defer archive.Close()
	waybackCDXEndpoint = archive.URL

	e := NewExtractor(true, false)
	opts := CrawlOptions{
		MaxDepth: 3, MaxPages: 50, SameScopeOnly: true,
		AutoCalibrate: true, Concurrency: 4,
		DiscoverPassive: true, PassiveSources: []string{passiveSourceWayback}, PassiveMax: 10,
		Permute: true, PermuteMax: 50,
	}
	var stats CrawlStats
	opts.OnComplete = func(s CrawlStats) { stats = s }
	ms, err := e.ScanURLCrawl(target.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !containsMatchValue(ms, secret) || secretHits.Load() != 1 {
		t.Fatalf("validated passive path did not reach permuted secret: hits=%d matches=%v", secretHits.Load(), ms)
	}
	if containsMatchValue(ms, staleSecret) {
		t.Fatalf("rejected passive 404 body was scanned: matches=%v", ms)
	}
	if stalePermuteHits.Load() != 0 {
		t.Fatalf("rejected passive path entered permutation dictionary (%d synthetic hits)", stalePermuteHits.Load())
	}
	if historicalQueryReplayed.Load() {
		t.Fatal("historical query value was replayed against the live target")
	}
	if stats.PassiveFound != 2 || stats.PassiveEnqueued != 2 ||
		stats.PassiveValidated != 1 || stats.PassiveRejected != 1 {
		t.Fatalf("unexpected passive telemetry: %+v", stats)
	}
}

func TestPassiveResponseStatusValidation(t *testing.T) {
	for _, status := range []int{200, 204, 301, 401, 403, 405} {
		if !passiveResponseStatusValid(status) {
			t.Errorf("status %d should prove a route exists", status)
		}
	}
	for _, status := range []int{100, 404, 410, 429, 500, 503} {
		if passiveResponseStatusValid(status) {
			t.Errorf("status %d should not validate a passive path", status)
		}
	}
}

func TestResumedPassiveTargetKeepsStrictValidation(t *testing.T) {
	const staleSecret = "eyJhbGciOiJIUzI1NiJ9.eyJyZXN1bWUiOjF9.resumedStaleMustNotScan"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `const stale="`+staleSecret+`";`)
	}))
	defer target.Close()

	pending := target.URL + "/historical.js"
	checkpoint := filepath.Join(t.TempDir(), "passive-resume.json")
	if err := writeCheckpoint(checkpoint, crawlCheckpoint{
		Version:  crawlCheckpointVersion,
		Seed:     normalizeCrawlURL(target.URL),
		Enqueued: []string{pending},
		Frontier: []checkpointTarget{{
			URL: pending, PassiveSource: passiveSourceWayback,
		}},
		Passive: passiveCheckpointStats{Found: 1, Enqueued: 1},
	}); err != nil {
		t.Fatal(err)
	}

	// Deliberately omit DiscoverPassive on resume. Provenance in the checkpoint
	// must still force validation rather than silently trusting the pending hint.
	var stats CrawlStats
	e := NewExtractor(true, false)
	ms, err := e.ScanURLCrawl(target.URL, false, false, false, CrawlOptions{
		MaxDepth: 1, MaxPages: 5, SameScopeOnly: true,
		ResumeFile: checkpoint, OnComplete: func(s CrawlStats) { stats = s },
	})
	if err != nil {
		t.Fatal(err)
	}
	if containsMatchValue(ms, staleSecret) {
		t.Fatalf("resumed passive 404 body was scanned: %v", ms)
	}
	if stats.PassiveFound != 1 || stats.PassiveEnqueued != 1 ||
		stats.PassiveValidated != 0 || stats.PassiveRejected != 1 {
		t.Fatalf("resumed passive telemetry was not preserved: %+v", stats)
	}
}

func containsMatchValue(ms []Match, value string) bool {
	for _, m := range ms {
		if m.Value == value {
			return true
		}
	}
	return false
}
