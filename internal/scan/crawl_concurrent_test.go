package scan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// jwtValues collects the distinct JWT match values from a result set, so a test
// can assert not just that a secret was reached but that every distinct secret
// across a fanned-out link graph was.
func jwtValues(ms []Match) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range ms {
		if m.Pattern != "jwt" {
			continue
		}
		if _, ok := seen[m.Value]; ok {
			continue
		}
		seen[m.Value] = struct{}{}
		out = append(out, m.Value)
	}
	sort.Strings(out)
	return out
}

// fanOutServer serves a seed that links n leaf pages, each of which links its own
// otherwise-unreferenced JS bundle holding a distinct JWT. Reaching every secret
// therefore requires crawling every leaf and following each leaf's script — the
// work a concurrent crawl spreads across its workers.
func fanOutServer(n int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			var b strings.Builder
			b.WriteString(`<html><script>`)
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "fetch('/p%d');", i)
			}
			b.WriteString(`</script></html>`)
			io.WriteString(w, b.String())
		case strings.HasPrefix(r.URL.Path, "/p"):
			i := strings.TrimPrefix(r.URL.Path, "/p")
			fmt.Fprintf(w, `<html><body><h1>page %s</h1><script src="/s%s.js"></script></body></html>`, i, i)
		}
	})
	// The /sN.js bundles are served by bundleMux, which wraps this mux and matches
	// them by prefix before delegating everything else here.
	return httptest.NewServer(bundleMux(mux))
}

// bundleMux wraps mux with a handler for the /sN.js bundles, each carrying a
// distinct, valid-looking JWT so the crawl reports one secret per leaf.
func bundleMux(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/s") && strings.HasSuffix(r.URL.Path, ".js") {
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/s"), ".js")
			w.Header().Set("Content-Type", "application/javascript")
			// A distinct JWT per bundle: the payload segment varies by id.
			fmt.Fprintf(w, "var token='eyJhbGciOiJIUzI1NiJ9.eyJpZCI6%s0000000000.sIgNaTuReValue%s';", id, id)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// TestScanURLCrawlConcurrentReachesAll verifies a concurrent crawl reaches every
// secret a serial crawl does — parallelism must not drop pages from the graph —
// and that the two produce the same set of secrets.
func TestScanURLCrawlConcurrentReachesAll(t *testing.T) {
	const n = 25
	ts := fanOutServer(n)
	defer ts.Close()

	e := NewExtractor(true, false)

	// Reachability test: isolate the link graph from dedup/probing so the counts
	// are exact. Depth 2 comfortably covers seed -> leaf (the leaf's own script is
	// followed while the leaf is scanned, not as a further hop).
	base := CrawlOptions{MaxDepth: 2, MaxPages: 0, SameScopeOnly: true}

	serialOpts := base
	serialOpts.Concurrency = 1
	serial, err := e.ScanURLCrawl(ts.URL, false, false, false, serialOpts)
	if err != nil {
		t.Fatal(err)
	}
	serialJWTs := jwtValues(serial)
	if len(serialJWTs) != n {
		t.Fatalf("serial crawl found %d distinct JWTs, want %d", len(serialJWTs), n)
	}

	concOpts := base
	concOpts.Concurrency = 8
	concurrent, err := e.ScanURLCrawl(ts.URL, false, false, false, concOpts)
	if err != nil {
		t.Fatal(err)
	}
	concJWTs := jwtValues(concurrent)
	if len(concJWTs) != n {
		t.Fatalf("concurrent crawl found %d distinct JWTs, want %d", len(concJWTs), n)
	}
	if !equalStrings(serialJWTs, concJWTs) {
		t.Fatalf("concurrent crawl reached a different secret set than serial\nserial:     %v\nconcurrent: %v", serialJWTs, concJWTs)
	}
}

// TestScanURLCrawlConcurrentMaxPages verifies the page budget is honoured exactly
// even when many targets are ready at once and several workers are dispatching in
// parallel: the cap counts pages dispatched, so a wide frontier cannot overshoot.
func TestScanURLCrawlConcurrentMaxPages(t *testing.T) {
	var pages chanCounter
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pages.inc()
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			// A wide fan-out: 40 distinct leaves are all enqueued after the seed, so
			// with several workers the crawl could overshoot a naive cap.
			var b strings.Builder
			b.WriteString(`<html><script>`)
			for i := 0; i < 40; i++ {
				fmt.Fprintf(&b, "fetch('/leaf%d');", i)
			}
			b.WriteString(`</script></html>`)
			io.WriteString(w, b.String())
			return
		}
		io.WriteString(w, `<html><body>leaf</body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	// Isolate page counting: no probing/calibration/well-known/dedup extra requests.
	opts := CrawlOptions{MaxDepth: 5, MaxPages: 5, SameScopeOnly: true, Concurrency: 8}
	if _, err := e.ScanURLCrawl(ts.URL, true, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if got := pages.count(); got != 5 {
		t.Fatalf("concurrent crawl fetched %d pages under a cap of 5, want exactly 5", got)
	}
}
