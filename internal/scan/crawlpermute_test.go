package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
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

// TestPermuterCrossLevel checks the core behaviour of the chosen model — the
// whole relative path is prefixed under every discovered level — including the
// retroactive case where a path and a level are discovered on different pages,
// each combination emitted exactly once.
func TestPermuterCrossLevel(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 0)

	// First target /api/users teaches the path "api/users" and levels /api/, /.
	// The full path is prefixed under each level, e.g. /api/ -> /api/api/users.
	first := p.observe([]string{"https://x.com/api/users"})
	if !contains(first, "https://x.com/api/api/users") {
		t.Fatalf("expected full path prefixed under /api/, got %v", first)
	}

	// A later target under a brand-new /shop/ level must pull the earlier
	// "api/users" path under /shop/ too — the retroactive cross product — and its
	// own "shop/thing" path back under the older /api/ level.
	second := p.observe([]string{"https://x.com/shop/thing"})
	if !contains(second, "https://x.com/shop/api/users") {
		t.Fatalf("expected earlier path re-tried under the new /shop/ level, got %v", second)
	}
	if !contains(second, "https://x.com/api/shop/thing") {
		t.Fatalf("expected new path tried under the older /api/ level, got %v", second)
	}

	// Nothing is emitted twice across the whole run.
	seen := map[string]struct{}{}
	for _, u := range append(first, second...) {
		if _, dup := seen[u]; dup {
			t.Fatalf("combination emitted twice: %s", u)
		}
		seen[u] = struct{}{}
	}
}

// TestPermuterCap stops emitting once the cap is reached.
func TestPermuterCap(t *testing.T) {
	p := newPermuter("https://x.com", "x.com", 2)
	out := p.observe([]string{
		"https://x.com/a/one", "https://x.com/b/two", "https://x.com/c/three",
	})
	if len(out) > 2 {
		t.Fatalf("cap of 2 exceeded: %d generated (%v)", len(out), out)
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
	permOpts.PermuteMax = 200
	permuted, err := e.ScanURLCrawl(ts.URL+"/", false, false, false, permOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(permuted, "jwt") {
		t.Fatalf("expected the jwt reached via cross-level permutation, got %+v", permuted)
	}
}
