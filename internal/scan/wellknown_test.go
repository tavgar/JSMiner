package scan

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gzipBytes(s string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(s))
	zw.Close()
	return buf.Bytes()
}

func TestRobotsPathPrefix(t *testing.T) {
	cases := map[string]string{
		"/admin/":     "/admin/",
		"/admin/*":    "/admin/", // wildcard trimmed to the concrete prefix
		"/search?q=*": "/search?q=",
		"/*.php$":     "", // starts with wildcard -> nothing useful
		"/":           "", // bare root is not a useful seed
		"":            "",
		"relative":    "", // not rooted
		"/api/v2$":    "/api/v2",
	}
	for in, want := range cases {
		if got := robotsPathPrefix(in); got != want {
			t.Errorf("robotsPathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRobots(t *testing.T) {
	body := strings.Join([]string{
		"# comment",
		"User-agent: *",
		"Disallow: /admin/",
		"Disallow: /tmp/*",
		"Allow: /public/api",
		"Disallow: /", // dropped: bare root
		"Sitemap: https://example.test/sitemap_index.xml",
		"sitemap: https://example.test/news-sitemap.xml",
	}, "\n")

	dirs, sitemaps, _ := parseRobots(body, "https://example.test")
	wantDirs := map[string]bool{
		"https://example.test/admin/":     true,
		"https://example.test/tmp/":       true,
		"https://example.test/public/api": true,
	}
	if len(dirs) != len(wantDirs) {
		t.Fatalf("dirs = %v, want %d entries", dirs, len(wantDirs))
	}
	for _, d := range dirs {
		if !wantDirs[d] {
			t.Errorf("unexpected dir %q", d)
		}
	}
	if len(sitemaps) != 2 {
		t.Fatalf("sitemaps = %v, want 2", sitemaps)
	}
}

func TestMaybeGunzip(t *testing.T) {
	plain := []byte("<urlset></urlset>")
	if got := maybeGunzip(plain); string(got) != string(plain) {
		t.Errorf("plain data should pass through unchanged, got %q", got)
	}
	gz := gzipBytes("<urlset><url><loc>https://e.test/a</loc></url></urlset>")
	got := maybeGunzip(gz)
	if !strings.Contains(string(got), "https://e.test/a") {
		t.Errorf("gzip data should be decompressed, got %q", got)
	}
	// Gzip magic but truncated/garbage body -> nil (unreadable stream).
	if got := maybeGunzip([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00}); got != nil {
		t.Errorf("corrupt gzip should return nil, got %q", got)
	}
}

func TestLooksLikeSitemap(t *testing.T) {
	yes := []string{"https://e.test/sitemap.xml", "https://e.test/sitemap_index.xml",
		"https://e.test/sitemaps/products-sitemap.xml", "https://e.test/sitemap.xml?page=2",
		"https://e.test/sitemap.xml.gz", "https://e.test/products-sitemap.xml.gz"}
	no := []string{"https://e.test/products/1", "https://e.test/data.xml", "https://e.test/about",
		"https://e.test/archive.tar.gz"}
	for _, u := range yes {
		if !looksLikeSitemap(u) {
			t.Errorf("looksLikeSitemap(%q) = false, want true", u)
		}
	}
	for _, u := range no {
		if looksLikeSitemap(u) {
			t.Errorf("looksLikeSitemap(%q) = true, want false", u)
		}
	}
}

// TestDiscoverWellKnownURLs drives the whole pipeline against a local server:
// robots.txt points at a sitemap index, which points at a child sitemap of pages;
// the discovered set must include the robots directories and the sitemap pages,
// follow the index recursively, and honour scope via the caller.
func TestDiscoverWellKnownURLs(t *testing.T) {
	var origin string
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nDisallow: /admin/\nAllow: /portal/login\nSitemap: %s/sitemap_index.xml\n", origin)
	})
	mux.HandleFunc("/sitemap_index.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0"?><sitemapindex><sitemap><loc>%s/pages-sitemap.xml</loc></sitemap></sitemapindex>`, origin)
	})
	mux.HandleFunc("/pages-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0"?><urlset>
			<url><loc>%s/products/42?ref=a&amp;b=2</loc></url>
			<url><loc>%s/about-us</loc></url>
		</urlset>`, origin, origin)
	})
	// The conventional /sitemap.xml also exists and should be picked up.
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<urlset><url><loc>%s/from-default-sitemap</loc></url></urlset>`, origin)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origin = srv.URL

	got := map[string]bool{}
	urls, _ := discoverWellKnownURLs(origin)
	for _, u := range urls {
		got[u] = true
	}
	want := []string{
		origin + "/admin/",
		origin + "/portal/login",
		origin + "/products/42?ref=a&b=2", // &amp; decoded
		origin + "/about-us",
		origin + "/from-default-sitemap",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing discovered URL %q (got %v)", w, keysOf(got))
		}
	}
	// The sitemap index and sitemap docs themselves must not be returned as pages.
	for u := range got {
		if looksLikeSitemap(u) {
			t.Errorf("sitemap document %q leaked into page results", u)
		}
	}
}

// TestDiscoverWellKnownURLsGzipped verifies the pipeline transparently handles
// gzipped sitemaps: robots.txt points at a gzipped sitemap index, which points at
// a gzipped child sitemap of pages, and all page URLs are still recovered.
func TestDiscoverWellKnownURLsGzipped(t *testing.T) {
	var origin string
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Sitemap: %s/sitemap_index.xml.gz\n", origin)
	})
	mux.HandleFunc("/sitemap_index.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(gzipBytes(fmt.Sprintf(
			`<sitemapindex><sitemap><loc>%s/pages.xml.gz</loc></sitemap></sitemapindex>`, origin)))
	})
	mux.HandleFunc("/pages.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(gzipBytes(fmt.Sprintf(
			`<urlset><url><loc>%s/gz-page-1</loc></url><url><loc>%s/gz-page-2</loc></url></urlset>`, origin, origin)))
	})
	// No plain /sitemap.xml here (404), so discovery must come from the gz chain.
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origin = srv.URL

	got := map[string]bool{}
	urls, _ := discoverWellKnownURLs(origin)
	for _, u := range urls {
		got[u] = true
	}
	for _, want := range []string{origin + "/gz-page-1", origin + "/gz-page-2"} {
		if !got[want] {
			t.Errorf("missing gzipped-sitemap URL %q (got %v)", want, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestWellKnownInScope verifies the sitemap-fetch scope guard: target-controlled
// pointers at foreign, internal or metadata hosts (and non-http schemes) are
// rejected before any fetch, while the seed host and its subdomains are allowed.
// This is the check that stops a hostile robots.txt from steering the crawler's
// fetches into an SSRF.
func TestWellKnownInScope(t *testing.T) {
	const origin = "example.com"
	allow := []string{
		"http://example.com/sitemap.xml",
		"https://example.com/a/b/sitemap.xml",
		"https://cdn.example.com/sitemap.xml", // subdomain
		"https://www.example.com/sitemap.xml",
	}
	for _, u := range allow {
		if !wellKnownInScope(origin, u) {
			t.Errorf("wellKnownInScope(%q, %q) = false, want true", origin, u)
		}
	}

	deny := []string{
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://localhost/sitemap.xml",
		"http://internal.corp/sitemap.xml",
		"https://evil.test/sitemap.xml",
		"http://example.com.evil.test/sitemap.xml", // suffix trick
		"file:///etc/passwd",
		"ftp://example.com/sitemap.xml",
		"gopher://example.com/",
		"not a url",
	}
	for _, u := range deny {
		if wellKnownInScope(origin, u) {
			t.Errorf("wellKnownInScope(%q, %q) = true, want false", origin, u)
		}
	}
}

// TestWellKnownSameOriginStillFollowed confirms the guard does not break normal
// discovery: a same-origin robots.txt Sitemap: pointer and its pages are found.
func TestWellKnownSameOriginStillFollowed(t *testing.T) {
	ResetThrottle()
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Sitemap: %s/my-sitemap.xml\n", "http://"+r.Host)
	})
	mux.HandleFunc("/my-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<urlset><url><loc>http://%s/legit-page</loc></url></urlset>`, r.Host)
	})
	seed := httptest.NewServer(mux)
	defer seed.Close()

	got, _ := discoverWellKnownURLs(seed.URL)
	found := false
	for _, u := range got {
		if strings.HasSuffix(u, "/legit-page") {
			found = true
		}
	}
	if !found {
		t.Fatalf("same-origin sitemap page not discovered; got %v", got)
	}
}
