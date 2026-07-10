package scan

import (
	"net/url"
	"path"
	"strings"
)

// CrawlOptions configures a breadth-first crawl seeded from a single URL.
//
// A crawl scans the seed page, harvests the endpoints it discovers
// (endpoint_url/endpoint_path and, for POST crawls, post_url/post_path),
// resolves the in-scope ones to absolute URLs and fetches them too, repeating
// until the depth or page budget is exhausted. Each fetched page is scanned
// with the normal rules, so crawling reaches JavaScript bundles — and the
// secrets in them — that are only linked from deeper pages or API responses.
type CrawlOptions struct {
	// MaxDepth is the number of link hops to follow beyond the seed page. A
	// depth of 0 scans only the seed (matching a plain ScanURL); 1 also scans
	// endpoints found on the seed, and so on.
	MaxDepth int

	// MaxPages caps the total number of pages fetched by the crawl, protecting
	// against runaway link graphs and parameterised URL explosions. Zero means
	// no cap (bounded only by MaxDepth and scope).
	MaxPages int

	// SameScopeOnly restricts crawling to the seed host and its subdomains (see
	// sameScope). Off-scope endpoints are still reported when they surface as
	// matches, they are simply not crawled. This is the expected default: the
	// user asked to follow discovered URLs only when they match the host.
	SameScopeOnly bool

	// AutoCalibrate turns on ffuf-style auto-calibration: before crawling, the
	// target is probed with random paths to learn its catch-all/soft-404
	// fingerprint, and pages matching that fingerprint — or duplicating a page
	// already scanned — are skipped so the crawl stays on unique, useful pages.
	AutoCalibrate bool

	// Progress, when non-nil, is invoked once per fetched page with the page
	// URL, its depth from the seed and the running page count. It lets the CLI
	// surface crawl progress without the scan package depending on the output
	// layer.
	Progress func(pageURL string, depth, pageNum int)

	// OnCalibrated, when non-nil, is invoked once after auto-calibration with
	// the number of wildcard signatures learned.
	OnCalibrated func(wildcardSigs int)
}

// DefaultCrawlOptions returns sensible defaults for interactive use: follow two
// hops beyond the seed, stay on the seed host and stop after 200 pages.
func DefaultCrawlOptions() CrawlOptions {
	return CrawlOptions{MaxDepth: 2, MaxPages: 200, SameScopeOnly: true}
}

// crawlTarget is a queued page together with its distance from the seed.
type crawlTarget struct {
	url   string
	depth int
}

// ScanURLCrawl scans urlStr and then crawls the in-scope endpoints it
// discovers, returning the deduplicated union of all matches. When endpoints is
// true only endpoint matches are produced (as with ScanURL). external controls
// whether off-scope script/import references are followed while scanning an
// individual page; the page-to-page crawl itself is governed by opts.
func (e *Extractor) ScanURLCrawl(urlStr string, endpoints, external, render bool, opts CrawlOptions) ([]Match, error) {
	scanPage := func(u, baseHost string, visited map[string]struct{}) ([]Match, error) {
		return e.scanURL(u, baseHost, endpoints, visited, external, render)
	}
	return e.crawlBFS(urlStr, opts, scanPage)
}

// ScanURLPostsCrawl behaves like ScanURLCrawl but scans each page for HTTP POST
// request endpoints, following the discovered endpoints to reach deeper pages.
func (e *Extractor) ScanURLPostsCrawl(urlStr string, external, render bool, opts CrawlOptions) ([]Match, error) {
	scanPage := func(u, baseHost string, visited map[string]struct{}) ([]Match, error) {
		return e.scanURLPosts(u, baseHost, visited, external, render)
	}
	return e.crawlBFS(urlStr, opts, scanPage)
}

// crawlBFS drives the breadth-first crawl. scanPage scans a single page (and,
// via scanURL/scanURLPosts, its script/import graph) and returns its matches;
// crawlBFS harvests fresh in-scope targets from those matches and keeps going.
//
// The visited map is shared across every scanPage call so a JS bundle
// referenced from many pages is fetched and scanned only once. The enqueued map
// tracks page-level targets so each page is crawled at most once.
func (e *Extractor) crawlBFS(seedURL string, opts CrawlOptions, scanPage func(u, baseHost string, visited map[string]struct{}) ([]Match, error)) ([]Match, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, err
	}
	baseHost := seed.Hostname()

	if opts.AutoCalibrate {
		c := newAutoCalibrator()
		n := c.calibrate(seed.String())
		e.SetCalibrator(c)
		defer e.SetCalibrator(nil)
		if opts.OnCalibrated != nil {
			opts.OnCalibrated(n)
		}
	}

	visited := make(map[string]struct{})
	enqueued := make(map[string]struct{})

	start := normalizeCrawlURL(seed.String())
	queue := []crawlTarget{{url: start, depth: 0}}
	enqueued[start] = struct{}{}

	var all []Match
	pages := 0
	for len(queue) > 0 {
		if opts.MaxPages > 0 && pages >= opts.MaxPages {
			break
		}
		t := queue[0]
		queue = queue[1:]
		pages++
		if opts.Progress != nil {
			opts.Progress(t.url, t.depth, pages)
		}

		ms, err := scanPage(t.url, baseHost, visited)
		if err != nil {
			continue
		}
		all = append(all, ms...)

		if t.depth >= opts.MaxDepth {
			continue
		}
		for _, next := range crawlTargetsFromMatches(ms, t.url, baseHost, opts) {
			if _, ok := enqueued[next]; ok {
				continue
			}
			enqueued[next] = struct{}{}
			queue = append(queue, crawlTarget{url: next, depth: t.depth + 1})
		}
	}

	return UniqueMatches(all), nil
}

// crawlTargetsFromMatches derives the next set of crawlable page URLs from the
// endpoint matches found on pageURL. Endpoint values are resolved against the
// page URL, filtered to http(s), optionally constrained to the seed scope and
// stripped of obvious binary assets that would waste a fetch.
func crawlTargetsFromMatches(ms []Match, pageURL, baseHost string, opts CrawlOptions) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range ms {
		switch m.Pattern {
		case "endpoint_url", "endpoint_path", "post_url", "post_path":
		default:
			continue
		}
		abs := resolveURL(pageURL, m.Value)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if opts.SameScopeOnly && !sameScope(baseHost, u.Hostname()) {
			continue
		}
		if !crawlableTarget(u) {
			continue
		}
		n := normalizeCrawlURL(u.String())
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// normalizeCrawlURL canonicalises a URL for crawl bookkeeping by dropping the
// fragment, which never changes what the server returns. The query is retained
// because it can select a distinct resource; the page budget bounds any
// parameter explosion.
func normalizeCrawlURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	return u.String()
}

// nonCrawlableExts are asset types that cannot yield further JavaScript,
// endpoints or secrets, so fetching them during a crawl is pure overhead.
var nonCrawlableExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {}, ".webp": {},
	".ico": {}, ".bmp": {}, ".tiff": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
	".mp4": {}, ".webm": {}, ".mp3": {}, ".wav": {}, ".ogg": {}, ".avi": {},
	".mov": {}, ".mkv": {},
	".zip": {}, ".gz": {}, ".tar": {}, ".rar": {}, ".7z": {}, ".bz2": {},
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {},
	".pptx": {},
}

// crawlableTarget reports whether u is worth fetching during a crawl. Binary
// assets (images, fonts, media, archives, documents) are skipped; everything
// else — HTML pages, JS, JSON, extensionless routes and API paths — is kept.
func crawlableTarget(u *url.URL) bool {
	ext := strings.ToLower(path.Ext(u.Path))
	if ext == "" {
		return true
	}
	_, skip := nonCrawlableExts[ext]
	return !skip
}
