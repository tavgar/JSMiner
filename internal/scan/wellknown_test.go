package scan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

	dirs, sitemaps := parseRobots(body, "https://example.test")
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

func TestLooksLikeSitemap(t *testing.T) {
	yes := []string{"https://e.test/sitemap.xml", "https://e.test/sitemap_index.xml",
		"https://e.test/sitemaps/products-sitemap.xml", "https://e.test/sitemap.xml?page=2"}
	no := []string{"https://e.test/products/1", "https://e.test/data.xml", "https://e.test/about"}
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
	for _, u := range discoverWellKnownURLs(origin) {
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

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
