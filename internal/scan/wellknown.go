package scan

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// Well-known discovery reads the URLs a site declares about itself — robots.txt
// (Allow/Disallow directories and Sitemap: pointers) and the XML sitemaps those
// point to (plus the conventional /sitemap.xml) — and feeds them into the crawl
// as extra seeds. These are real, server-published paths, so they surface pages
// and API roots that no page happens to link to and that static JS scanning never
// reveals, without resorting to guessing.
//
// It is bounded on every axis so a giant or self-referential sitemap cannot run
// away: a cap on sitemap documents fetched, a recursion cap for sitemap indexes,
// and a cap on total URLs returned. The crawl's own page budget bounds what is
// actually fetched afterwards.
const (
	// wellKnownMaxURLs caps how many discovered URLs are handed to the crawl.
	wellKnownMaxURLs = 500

	// wellKnownMaxSitemaps caps how many sitemap documents are fetched, so a
	// sitemap index pointing at hundreds of child sitemaps cannot fan out
	// unboundedly.
	wellKnownMaxSitemaps = 20

	// wellKnownMaxDecompressed caps the size of a gunzipped sitemap so a
	// gzip-bomb sitemap.xml.gz cannot exhaust memory.
	wellKnownMaxDecompressed = 32 << 20
)

var (
	// robotsDirectiveRe captures an Allow/Disallow path value from a robots.txt line.
	robotsDirectiveRe = regexp.MustCompile(`(?i)^\s*(?:dis)?allow\s*:\s*(\S+)`)
	// robotsSitemapRe captures a Sitemap: URL from a robots.txt line.
	robotsSitemapRe = regexp.MustCompile(`(?i)^\s*sitemap\s*:\s*(\S+)`)
	// sitemapLocRe captures a <loc> URL from a sitemap or sitemap index document.
	sitemapLocRe = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)
)

// discoverWellKnownURLs fetches robots.txt and the sitemaps it (and convention)
// advertise for origin, returning the absolute in-origin URLs it found. origin is
// scheme://host with no trailing slash. The result is de-duplicated and capped at
// wellKnownMaxURLs; ordering follows discovery so robots directories come first.
func discoverWellKnownURLs(origin string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) bool {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return true
		}
		if _, ok := seen[raw]; ok {
			return true
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
		return len(out) < wellKnownMaxURLs
	}

	// robots.txt: directory hints plus explicit sitemap pointers.
	sitemaps := []string{origin + "/sitemap.xml"}
	if body, ok := fetchWellKnownBody(origin + "/robots.txt"); ok {
		dirs, sm := parseRobots(body, origin)
		sitemaps = append(sitemaps, sm...)
		for _, d := range dirs {
			if !add(d) {
				return out
			}
		}
	}

	// Sitemaps, following <loc> entries and recursing into sitemap indexes, all
	// bounded so a hostile document cannot exhaust the budget.
	fetched := make(map[string]struct{})
	queue := dedupeStrings(sitemaps)
	docs := 0
	for len(queue) > 0 && docs < wellKnownMaxSitemaps {
		sm := queue[0]
		queue = queue[1:]
		if _, ok := fetched[sm]; ok {
			continue
		}
		fetched[sm] = struct{}{}
		body, ok := fetchWellKnownBody(sm)
		if !ok {
			continue
		}
		docs++
		// Classify <loc> entries by the document type, which is authoritative: a
		// sitemap index's children are always further sitemaps to fetch, a urlset's
		// entries are always pages. Fall back to the URL-name heuristic only for a
		// document whose root element is neither (malformed or truncated).
		isIndex := strings.Contains(strings.ToLower(body), "<sitemapindex")
		isURLSet := strings.Contains(strings.ToLower(body), "<urlset")
		for _, loc := range sitemapLocRe.FindAllStringSubmatch(body, -1) {
			locURL := decodeXMLEntities(strings.TrimSpace(loc[1]))
			if locURL == "" {
				continue
			}
			childSitemap := isIndex || (!isURLSet && looksLikeSitemap(locURL))
			if childSitemap {
				if _, done := fetched[locURL]; !done {
					queue = append(queue, locURL)
				}
				continue
			}
			if !add(locURL) {
				return out
			}
		}
	}
	return out
}

// parseRobots extracts crawlable directory URLs and Sitemap: pointers from a
// robots.txt body. Allow/Disallow values are resolved against origin; pattern
// values are reduced to the concrete prefix before their first wildcard so a rule
// like "Disallow: /admin/*" still yields the real "/admin/" directory, while a
// value that reduces to nothing useful (e.g. "/" or "/*.php$") is dropped.
func parseRobots(body, origin string) (dirs, sitemaps []string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := robotsSitemapRe.FindStringSubmatch(line); m != nil {
			sitemaps = append(sitemaps, strings.TrimSpace(m[1]))
			continue
		}
		if m := robotsDirectiveRe.FindStringSubmatch(line); m != nil {
			p := robotsPathPrefix(m[1])
			if p == "" {
				continue
			}
			if abs := resolveWellKnownPath(origin, p); abs != "" {
				dirs = append(dirs, abs)
			}
		}
	}
	return dedupeStrings(dirs), dedupeStrings(sitemaps)
}

// robotsPathPrefix reduces a robots.txt path value to the concrete, crawlable
// prefix before any wildcard, returning "" when nothing useful remains (the bare
// root, or a rule that starts with a wildcard).
func robotsPathPrefix(val string) string {
	val = strings.TrimSpace(val)
	if i := strings.IndexAny(val, "*$"); i >= 0 {
		val = val[:i]
	}
	if val == "" || val == "/" {
		return ""
	}
	if !strings.HasPrefix(val, "/") {
		return ""
	}
	return val
}

// resolveWellKnownPath joins a rooted path onto origin, returning "" if the result
// is not a valid absolute URL.
func resolveWellKnownPath(origin, p string) string {
	u, err := url.Parse(origin + p)
	if err != nil {
		return ""
	}
	return u.String()
}

// looksLikeSitemap reports whether a <loc> URL is itself a sitemap document
// (a sitemap index entry) rather than a content page, so it is fetched and parsed
// instead of crawled.
func looksLikeSitemap(raw string) bool {
	lower := strings.ToLower(raw)
	if i := strings.IndexAny(lower, "?#"); i >= 0 {
		lower = lower[:i]
	}
	// A gzipped sitemap (sitemap.xml.gz) is still a sitemap document to fetch and
	// parse; strip the .gz so the .xml/sitemap tests below apply.
	lower = strings.TrimSuffix(lower, ".gz")
	return strings.HasSuffix(lower, "sitemap.xml") ||
		strings.HasSuffix(lower, ".xml") && strings.Contains(lower, "sitemap")
}

// fetchWellKnownBody GETs u through the shared (throttled) request path and
// returns its body as a string, capped so a large sitemap cannot exhaust memory.
// ok is false on any transport error or non-2xx status.
func fetchWellKnownBody(u string) (string, bool) {
	resp, err := fetchURLResponse(u)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", false
	}
	// A gzipped sitemap (commonly sitemap.xml.gz) is served as a gzip file, not
	// via Content-Encoding, so the HTTP client does not transparently decode it.
	// Detect the gzip magic bytes and decompress so the XML underneath is parsed
	// rather than mined as binary noise.
	if data = maybeGunzip(data); data == nil {
		return "", false
	}
	return string(data), true
}

// maybeGunzip decompresses data when it carries the gzip magic header, capping
// the decompressed output. It returns data unchanged when it is not gzip, and nil
// only when a gzip stream is present but cannot be read.
func maybeGunzip(data []byte) []byte {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, wellKnownMaxDecompressed))
	if err != nil {
		return nil
	}
	return out
}

// decodeXMLEntities expands the handful of XML entities a sitemap <loc> may carry
// (chiefly &amp; in query strings) so the recovered URL is usable.
func decodeXMLEntities(s string) string {
	r := strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&#39;", "'",
	)
	return r.Replace(s)
}

// dedupeStrings returns xs with duplicates removed, preserving first-seen order.
func dedupeStrings(xs []string) []string {
	seen := make(map[string]struct{}, len(xs))
	out := xs[:0:0]
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
