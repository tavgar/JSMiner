package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hitSet is a concurrency-safe record of which paths the test server was asked for.
type hitSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (h *hitSet) hit(p string) {
	h.mu.Lock()
	if h.m == nil {
		h.m = map[string]bool{}
	}
	h.m[p] = true
	h.mu.Unlock()
}

func (h *hitSet) got(p string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.m[p]
}

// TestCrawlPrioritisesHighYieldUnderCap verifies the frontier spends a tight page
// budget on the densest targets first: when the seed links a mix of high-yield
// bundles/APIs and low-yield HTML pages at the same depth, a MaxPages cap fetches
// the bundles/APIs and leaves the HTML pages behind.
func TestCrawlPrioritisesHighYieldUnderCap(t *testing.T) {
	var hits hitSet
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.hit(r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			// Four low-yield HTML pages and two high-yield targets, all depth 1.
			io.WriteString(w, `<html><script>`+
				`fetch('/a.html');fetch('/b.html');fetch('/c.html');fetch('/d.html');`+
				`fetch('/data.json');fetch('/bundle.js');`+
				`</script></html>`)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		io.WriteString(w, `ok`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	// Serial (Concurrency unset), no probing/calibration/dedup so only the frontier
	// order decides what the 3-page budget (seed + 2) is spent on.
	opts := CrawlOptions{MaxDepth: 2, MaxPages: 3, SameScopeOnly: true}
	if _, err := e.ScanURLCrawl(ts.URL, true, false, false, opts); err != nil {
		t.Fatal(err)
	}

	// The two high-yield targets should have been fetched.
	for _, p := range []string{"/bundle.js", "/data.json"} {
		if !hits.got(p) {
			t.Errorf("high-yield %s was not fetched under the cap", p)
		}
	}
	// The low-yield HTML pages should have been left outside the budget.
	for _, p := range []string{"/a.html", "/b.html", "/c.html", "/d.html"} {
		if hits.got(p) {
			t.Errorf("low-yield %s was fetched ahead of a higher-yield target", p)
		}
	}
}
