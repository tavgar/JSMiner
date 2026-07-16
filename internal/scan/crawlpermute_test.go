package scan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLevelsWithAncestors(t *testing.T) {
	got := levelsWithAncestors("https://x.com/api/v2/users")
	want := []string{"/api/v2/", "/api/", "/"}
	if !equalStrings(got, want) {
		t.Fatalf("levelsWithAncestors = %v, want %v", got, want)
	}
	if r := levelsWithAncestors("https://x.com/"); !equalStrings(r, []string{"/"}) {
		t.Fatalf("root levels = %v, want [/]", r)
	}
}

func candidateURLs(candidates []permuteCandidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.URL)
	}
	return out
}

// TestPermuterCrossLevel checks full-path permutation, retroactive combinations,
// known-URL suppression and one-time emission.
func TestPermuterCrossLevel(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)

	// A single path only teaches the pool. It does not spend requests on
	// self-prefix guesses such as /api/api/users.
	first := p.observe([]string{"https://x.com/api/users"})
	if len(first) != 0 {
		t.Fatalf("single-source observation emitted low-confidence permutations: %v", first)
	}

	// A later target under a brand-new /shop/ level must pull the earlier
	// "api/users" path under /shop/ too — the retroactive cross product — and its
	// own "shop/thing" path back under the older /api/ level.
	second := p.observe([]string{"https://x.com/shop/thing"})
	if !contains(candidateURLs(second), "https://x.com/shop/api/users") {
		t.Fatalf("expected earlier path re-tried under the new /shop/ level, got %v", second)
	}
	if !contains(candidateURLs(second), "https://x.com/api/shop/thing") {
		t.Fatalf("expected new path tried under the older /api/ level, got %v", second)
	}

	// Nothing is emitted twice across the whole run.
	seen := map[string]struct{}{}
	for _, candidate := range second {
		if _, dup := seen[candidate.URL]; dup {
			t.Fatalf("combination emitted twice: %s", candidate.URL)
		}
		seen[candidate.URL] = struct{}{}
	}
}

// TestPermuterCapCountsAdmissions verifies a rejected candidate does not spend
// the cap and the next candidate can still be admitted.
func TestPermuterCapCountsAdmissions(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 1)
	candidates := p.observe([]string{
		"https://x.com/a/app.js", "https://x.com/b/config.json",
	})
	if len(candidates) < 2 {
		t.Fatalf("need at least two candidates to exercise admission accounting: %v", candidates)
	}
	p.recordAdmission(false)
	if !p.hasBudget() {
		t.Fatal("rejected candidate consumed the permutation cap")
	}
	p.recordAdmission(true)
	if p.hasBudget() {
		t.Fatal("admitted candidate did not consume the permutation cap")
	}
	if p.stats.Admitted != 1 || p.stats.SkippedAdmission != 1 {
		t.Fatalf("unexpected admission stats: %+v", p.stats)
	}
}

func TestPermuterRanksUsefulCrossBranchCandidates(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)
	candidates := p.observe([]string{
		"https://x.com/api/users",
		"https://x.com/legacy/admin/config.js",
	})
	if len(candidates) == 0 {
		t.Fatal("expected permutation candidates")
	}
	if candidates[0].URL != "https://x.com/api/admin/config.js" {
		t.Fatalf("best candidate = %s (score %d), want cross-branch asset /api/admin/config.js; all=%v",
			candidates[0].URL, candidates[0].Score, candidates)
	}
	repeatedScore := 0
	for _, candidate := range candidates {
		if candidate.URL == "https://x.com/api/api/users" {
			repeatedScore = candidate.Score
		}
	}
	if repeatedScore == 0 || candidates[0].Score <= repeatedScore {
		t.Fatalf("cross-branch asset was not ranked above repeated prefix: %v", candidates)
	}
}

func TestPermuterBoundsCandidateMemoryToBestWindow(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 1)
	targets := []string{
		"https://x.com/api/status",
		"https://x.com/legacy/admin/config.js",
	}
	for i := 0; i < 50; i++ {
		targets = append(targets, fmt.Sprintf("https://x.com/section%d/page%d", i, i))
	}
	candidates := p.observe(targets)
	if len(candidates) > p.candidateWindow() {
		t.Fatalf("candidate window exceeded: got %d, limit %d", len(candidates), p.candidateWindow())
	}
	if p.stats.Pruned == 0 {
		t.Fatal("large cross-product did not prune lower-ranked candidates")
	}
	if len(candidates) == 0 || candidates[0].URL != "https://x.com/api/admin/config.js" {
		t.Fatalf("bounded ranking did not retain the best candidate: %v", candidates)
	}
}

func TestPermuterPreservesQueryAndEncodedPath(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)
	p.observe([]string{"https://x.com/api/status"})
	candidates := p.observe([]string{"https://x.com/files/a%2Fb/export.json?format=full"})

	var encoded, query bool
	for _, candidate := range candidates {
		if strings.Contains(candidate.URL, "a%2Fb") {
			encoded = true
		}
		u, err := url.Parse(candidate.URL)
		if err == nil && u.Query().Get("format") == "full" {
			query = true
		}
	}
	if !encoded {
		t.Fatalf("encoded slash was not preserved: %v", candidates)
	}
	if !query {
		t.Fatalf("query string was not preserved: %v", candidates)
	}
}

func TestPermuterPreservesTrailingSlashRoutes(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)
	p.observe([]string{"https://x.com/api/status"})
	candidates := p.observe([]string{"https://x.com/admin/"})
	if !contains(candidateURLs(candidates), "https://x.com/api/admin/") {
		t.Fatalf("trailing-slash route was not permuted intact: %v", candidates)
	}
}

func TestPermuterCrossesAPIVersionsWithEndpointBasename(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)
	p.observe([]string{"https://x.com/api/v1/users"})
	candidates := p.observe([]string{"https://x.com/api/v2/status"})
	if !contains(candidateURLs(candidates), "https://x.com/api/v2/users") {
		t.Fatalf("API endpoint basename was not reused across versions: %v", candidates)
	}
}

func TestPermuterKeepsOriginsIsolated(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)
	p.observe([]string{
		"https://x.com/api/status",
		"https://api.x.com/v1/status",
	})
	candidates := p.observe([]string{
		"https://x.com/admin/config.js",
		"https://api.x.com/internal/config.js",
	})
	for _, candidate := range candidates {
		u, err := url.Parse(candidate.URL)
		if err != nil {
			t.Fatal(err)
		}
		switch u.Hostname() {
		case "x.com":
			if strings.Contains(u.Path, "/internal/") {
				t.Fatalf("api.x.com path crossed into x.com pool: %s", candidate.URL)
			}
		case "api.x.com":
			if strings.Contains(u.Path, "/admin/") {
				t.Fatalf("x.com path crossed into api.x.com pool: %s", candidate.URL)
			}
		default:
			t.Fatalf("unexpected candidate origin: %s", candidate.URL)
		}
	}
}

// TestScanURLCrawlPermute is the end-to-end check for the full-path model: the
// secret lives in /api/admin/config.js. The crawl discovers the path
// "admin/config.js" (a decoy bundle under the root) and, separately, the /api/
// level; only cross-level permutation prefixes that whole path under /api/ to
// reach /api/admin/config.js.
func TestScanURLCrawlPermute(t *testing.T) {
	mux := http.NewServeMux()
	// Seed links a decoy /admin/config.js and an /api/status page (teaches /api/).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script>fetch('/admin/config.js');fetch('/api/status');</script></html>`)
	})
	// Decoy bundle: same relative path as the secret but under /admin/, no secret.
	mux.HandleFunc("/admin/config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `var ok=true;`)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>ok</body></html>`)
	})
	// Only reachable by prefixing "admin/config.js" under /api/.
	mux.HandleFunc("/api/admin/config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `const t='eyJabc.def.ghi';`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)

	base := CrawlOptions{MaxDepth: 3, MaxPages: 50, SameScopeOnly: true}

	// Without permutation the crawler never asks for /api/admin/config.js.
	plain, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, base)
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(plain, "jwt") {
		t.Fatal("did not expect the jwt without -crawl-permute")
	}

	// With permutation, "admin/config.js" (found under /) is prefixed under /api/.
	permOpts := base
	permOpts.Permute = true
	// A cap of one also checks that known identities and lower-value repeated
	// prefixes do not spend the budget before the best cross-branch asset.
	permOpts.PermuteMax = 1
	permOpts.Concurrency = 4
	var stats CrawlStats
	permOpts.OnComplete = func(s CrawlStats) { stats = s }
	permuted, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, permOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(permuted, "jwt") {
		t.Fatalf("expected the jwt reached via cross-level permutation, got %+v", permuted)
	}
	if stats.PermuteEnqueued != 1 || stats.PermuteFetched != 1 || stats.PermuteYielded != 1 {
		t.Fatalf("unexpected permutation telemetry: %+v", stats)
	}
	if stats.PermuteConsidered <= stats.PermuteEnqueued || stats.PermuteSkippedKnown == 0 {
		t.Fatalf("expected considered/known-skip accounting, got %+v", stats)
	}
}

func TestScanURLCrawlPermuteHonorsDepthConcurrent(t *testing.T) {
	var seedHits, deeperHits int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/status" {
			seedHits++
		} else {
			deeperHits++
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>ok</body></html>`)
	}))
	defer ts.Close()

	e := NewExtractor(true, false)
	opts := CrawlOptions{
		MaxDepth: 0, MaxPages: 20, SameScopeOnly: true,
		Permute: true, PermuteMax: 20, Concurrency: 4,
	}
	if _, err := e.ScanURLCrawl(ts.URL+"/api/status", false, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if seedHits != 1 || deeperHits != 0 {
		t.Fatalf("depth-0 concurrent permutation escaped its depth budget: seed=%d deeper=%d", seedHits, deeperHits)
	}
}
