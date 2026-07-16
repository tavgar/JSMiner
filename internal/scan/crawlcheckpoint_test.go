package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestCrawlCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	perm := newPermuter("https://x.com", "x.com", 10)
	perm.observe([]string{"https://x.com/admin/config.js", "https://x.com/api/status"})
	perm.recordAdmission(true)
	cp := crawlCheckpoint{
		Version:      crawlCheckpointVersion,
		Seed:         "https://x.com",
		Pages:        7,
		CrawlDelayMS: 2500,
		Visited:      []string{"https://x.com/a", "https://x.com/b"},
		Enqueued:     []string{"https://x.com/c"},
		Frontier: []checkpointTarget{{
			URL: "https://x.com/c", Depth: 2, Permuted: true,
			PassiveSource: passiveSourceWayback,
		}},
		Matches:  []Match{{Source: "https://x.com/a", Pattern: "jwt", Value: "tok", Severity: "high"}},
		Permuter: perm.snapshot(),
		Passive: passiveCheckpointStats{
			Found: 4, Enqueued: 3, Validated: 2, Rejected: 1,
		},
	}
	if err := writeCheckpoint(path, cp); err != nil {
		t.Fatal(err)
	}
	got, err := readCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seed != cp.Seed || got.Pages != cp.Pages || got.CrawlDelayMS != cp.CrawlDelayMS ||
		len(got.Visited) != 2 || len(got.Frontier) != 1 || got.Frontier[0].Depth != 2 ||
		!got.Frontier[0].Permuted || got.Frontier[0].PassiveSource != passiveSourceWayback ||
		len(got.Matches) != 1 || got.Matches[0].Value != "tok" ||
		got.Permuter == nil || got.Permuter.Stats.Admitted != 1 || len(got.Permuter.Pools) == 0 ||
		got.Passive.Found != 4 || got.Passive.Enqueued != 3 ||
		got.Passive.Validated != 2 || got.Passive.Rejected != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// A version bump makes an old checkpoint unreadable rather than misread.
	cp.Version = 999
	if err := writeCheckpoint(path, cp); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpoint(path); err == nil {
		t.Fatal("expected an error reading an incompatible-version checkpoint")
	}
}

// TestScanURLCrawlResumeRestoresPermuterState verifies a URL path learned before
// interruption can still combine with a level learned after resume.
func TestScanURLCrawlResumeRestoresPermuterState(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJyZXN1bWVkIjoxfQ.permuterResumeSignature"
	var secretHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>status</body></html>`)
	})
	mux.HandleFunc("/api/admin/config.js", func(w http.ResponseWriter, r *http.Request) {
		secretHits++
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const token="`+secret+`";`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	seedURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	perm := newPermuter(ts.URL, seedURL.Hostname(), 20)
	perm.observe([]string{ts.URL + "/admin/config.js"})

	state := filepath.Join(t.TempDir(), "resume-permute.json")
	cp := crawlCheckpoint{
		Version:  crawlCheckpointVersion,
		Seed:     normalizeCrawlURL(ts.URL),
		Pages:    1,
		Enqueued: []string{ts.URL + "/api/status"},
		Frontier: []checkpointTarget{{URL: ts.URL + "/api/status", Depth: 1}},
		Permuter: perm.snapshot(),
	}
	if err := writeCheckpoint(state, cp); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor(true, false)
	opts := CrawlOptions{
		MaxDepth: 3, MaxPages: 20, SameScopeOnly: true,
		Permute: true, PermuteMax: 20, ResumeFile: state,
	}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if secretHits != 1 || !hasPattern(ms, "jwt") {
		t.Fatalf("restored permuter did not reach secret: hits=%d matches=%+v", secretHits, ms)
	}
}

// TestScanURLCrawlResumesFromCheckpoint verifies a crawl started with a resume
// file continues from a pre-existing checkpoint: it carries the prior matches
// forward, does not re-fetch pages already marked visited, crawls the pending
// frontier to find new secrets, and removes the checkpoint on clean completion.
func TestScanURLCrawlResumesFromCheckpoint(t *testing.T) {
	const (
		priorSecret   = "eyJhbGciOiJIUzI1NiJ9.eyJwcmlvciI6MX0.priorRunSignatureAA"
		pendingSecret = "eyJhbGciOiJIUzI1NiJ9.eyJuZXh0Ijoxfe0.pendingSignatureBBBB"
	)
	var alreadyHits, pendingHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/already", func(w http.ResponseWriter, r *http.Request) {
		alreadyHits++
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>already visited</body></html>`)
	})
	mux.HandleFunc("/pending", func(w http.ResponseWriter, r *http.Request) {
		pendingHits++
		w.Header().Set("Content-Type", "text/html")
		// Links /already (which must be skipped as visited) and holds a secret.
		io.WriteString(w, `<html><script>var t='`+pendingSecret+`';fetch('/already');</script></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	state := filepath.Join(dir, "resume.json")
	seed := normalizeCrawlURL(ts.URL)
	cp := crawlCheckpoint{
		Version:  crawlCheckpointVersion,
		Seed:     seed,
		Pages:    1,
		Visited:  []string{ts.URL + "/already"},
		Enqueued: []string{ts.URL + "/already", ts.URL + "/pending"},
		Frontier: []checkpointTarget{{URL: ts.URL + "/pending", Depth: 1}},
		Matches:  []Match{{Source: ts.URL + "/seed.js", Pattern: "jwt", Value: priorSecret, Severity: "high"}},
	}
	if err := writeCheckpoint(state, cp); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor(true, false)
	opts := CrawlOptions{MaxDepth: 3, MaxPages: 50, SameScopeOnly: true, ResumeFile: state}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}

	found := func(v string) bool {
		for _, m := range ms {
			if m.Value == v {
				return true
			}
		}
		return false
	}
	if !found(priorSecret) {
		t.Error("prior run's match was not carried forward from the checkpoint")
	}
	if !found(pendingSecret) {
		t.Error("secret on the pending frontier page was not reached after resume")
	}
	if pendingHits != 1 {
		t.Errorf("/pending fetched %d times, want 1", pendingHits)
	}
	if alreadyHits != 0 {
		t.Errorf("/already was fetched %d times; a checkpoint-visited page must not be re-fetched", alreadyHits)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("checkpoint file should be removed after clean completion")
	}
}

// TestScanURLCrawlConcurrentCheckpointing exercises the concurrent driver's
// checkpoint path (with its in-flight bookkeeping) end to end under -race: a full
// crawl with a resume file must complete, reach every secret, and clean up.
func TestScanURLCrawlConcurrentCheckpointing(t *testing.T) {
	const n = 30
	ts := fanOutServer(n)
	defer ts.Close()

	dir := t.TempDir()
	state := filepath.Join(dir, "resume.json")

	e := NewExtractor(true, false)
	opts := CrawlOptions{MaxDepth: 2, MaxPages: 0, SameScopeOnly: true, Concurrency: 8, ResumeFile: state}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(jwtValues(ms)); got != n {
		t.Fatalf("found %d distinct JWTs, want %d", got, n)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("checkpoint file should be removed after clean completion")
	}
}

// TestScanURLCrawlResumeReplaysInflightAtPageCap models a checkpoint written
// while the only budgeted page was in flight. The pending page is persisted on
// the frontier and must not also count as completed, otherwise a resume at the
// exact page cap exits without ever fetching it.
func TestScanURLCrawlResumeReplaysInflightAtPageCap(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJpbmZsaWdodCI6MX0.resumePendingSignature"
	var hits int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const token="`+secret+`";`)
	}))
	defer ts.Close()

	state := filepath.Join(t.TempDir(), "resume.json")
	seed := normalizeCrawlURL(ts.URL + "/app.js")
	if got := checkpointCompletedPages(1, 1); got != 0 {
		t.Fatalf("checkpoint counted an in-flight dispatch as completed: got %d", got)
	}
	// This is the state produced by the fixed checkpoint writer: an in-flight
	// dispatch is on the frontier but not included in completed Pages.
	cp := crawlCheckpoint{
		Version:  crawlCheckpointVersion,
		Seed:     seed,
		Pages:    0,
		Enqueued: []string{seed},
		Frontier: []checkpointTarget{{URL: seed, Depth: 0}},
	}
	if err := writeCheckpoint(state, cp); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor(true, false)
	opts := CrawlOptions{MaxPages: 1, SameScopeOnly: true, ResumeFile: state, Concurrency: 2}
	ms, err := e.ScanURLCrawl(seed, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || !hasPattern(ms, "jwt") {
		t.Fatalf("pending page was not replayed within budget: hits=%d matches=%+v", hits, ms)
	}
}

// TestScanURLCrawlIgnoresCheckpointForDifferentSeed verifies a checkpoint written
// for another seed is ignored, so the crawl starts fresh rather than crawling a
// stale frontier that belongs to a different target.
func TestScanURLCrawlIgnoresCheckpointForDifferentSeed(t *testing.T) {
	var seedHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			seedHits++
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>fresh</body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	state := filepath.Join(dir, "resume.json")
	cp := crawlCheckpoint{
		Version:  crawlCheckpointVersion,
		Seed:     "https://some-other-host.example",
		Frontier: []checkpointTarget{{URL: "https://some-other-host.example/x", Depth: 1}},
	}
	if err := writeCheckpoint(state, cp); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor(true, false)
	opts := CrawlOptions{MaxDepth: 0, MaxPages: 5, SameScopeOnly: true, ResumeFile: state}
	if _, err := e.ScanURLCrawl(ts.URL, false, false, false, opts); err != nil {
		t.Fatal(err)
	}
	// The seed of THIS target must have been crawled (fresh start), not the stale
	// off-host frontier.
	if seedHits != 1 {
		t.Fatalf("seed fetched %d times; a mismatched checkpoint should start fresh", seedHits)
	}
}
