package scan

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

// newHTTPClient builds an HTTP client for the URL fetch helpers: a cloned default
// transport that optionally skips TLS verification, a request timeout and a
// redirect cap. The transport keeps a generous per-host idle-connection pool so a
// crawl reuses keep-alive connections instead of opening a fresh TCP+TLS
// connection for every one of its hundreds of requests to the same host.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The stdlib default is only 2 idle connections per host, which throttles
	// connection reuse the moment a crawl issues requests back to back (and, once
	// crawling is parallelised, forces extra handshakes). Raise it so the pool
	// spans a crawl's working set of hosts.
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 16
	if SkipTLSVerification {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   HTTPClientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// The crawl's hot path shares one HTTP client so its transport's keep-alive
// connection pool is reused across requests rather than discarded after each one.
// The client is rebuilt only when a setting baked into it changes (TLS
// verification or the request timeout), which happens once at startup in normal
// use, so a live crawl always reuses the same pooled connections.
var (
	httpClientMu      sync.Mutex
	sharedClient      *http.Client
	sharedClientTLS   bool
	sharedClientTOut  time.Duration
	sharedClientBuilt bool
)

// sharedHTTPClient returns the process-wide fetch client, (re)building it when the
// TLS or timeout settings baked into a cached client no longer match the current
// configuration. Reusing it is what lets consecutive requests to a host ride the
// same keep-alive connection instead of re-handshaking every time.
func sharedHTTPClient() *http.Client {
	httpClientMu.Lock()
	defer httpClientMu.Unlock()
	if !sharedClientBuilt || sharedClientTLS != SkipTLSVerification || sharedClientTOut != HTTPClientTimeout {
		sharedClient = newHTTPClient()
		sharedClientTLS = SkipTLSVerification
		sharedClientTOut = HTTPClientTimeout
		sharedClientBuilt = true
	}
	return sharedClient
}

// fetchURLResponse retrieves a URL with GET and returns the http.Response
// with limited redirects and a default User-Agent.
func fetchURLResponse(u string) (*http.Response, error) {
	return fetchURLResponseMethod(u, "GET", "")
}

// fetchURLResponseMethod retrieves u with the given HTTP method and returns the
// http.Response. When body is non-empty it is sent as the request body with a
// content type inferred from its shape (JSON when it starts with '{' or '[',
// form-encoded otherwise); this lets the crawler replay discovered POST/PUT/PATCH
// parameters against a target. The default User-Agent and any extra headers still
// apply.
func fetchURLResponseMethod(u, method, body string) (*http.Response, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, err
	}
	applyHeaders(req)
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", inferContentType(body))
	}
	// A transient transport error (connection reset, DNS blip, timeout) is retried
	// on the idempotent, bodyless fetch path so a single network hiccup does not
	// drop a page from the crawl. Requests that carry a body — discovered POST/PUT/
	// PATCH parameter replays — are attempted exactly once so a retry can never
	// double-submit them against the target.
	attempts := 1
	if body == "" {
		attempts += FetchRetries
	}
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		// Pace outbound requests so a crawl's burst of fetches, probes and
		// calibrations stays under the target's rate limit, and back off when the
		// server signals 429/503. wait() blocks for the configured/adaptive gap;
		// observe() adapts the gap to the response.
		host := hostOf(u)
		globalThrottle.waitHost(host)
		resp, err = sharedHTTPClient().Do(req)
		globalThrottle.observeHost(host, resp, err)
		if err == nil {
			break
		}
		if attempt+1 >= attempts {
			vlog(2, "http %s %s -> error: %v", method, u, err)
			return nil, err
		}
		vlog(2, "http %s %s -> transport error (%v); retry %d/%d", method, u, err, attempt+1, attempts-1)
	}
	vlog(2, "http %s %s -> %s", method, u, resp.Status)
	return resp, nil
}

// readCappedBody reads at most MaxResponseBodyBytes from a fetched response
// body, so a single response cannot exhaust memory during a crawl of untrusted
// hosts. It exists to keep the crawl's whole-body reads bounded the same way
// every other network read in the package (calibration, sitemaps, source maps)
// already is.
func readCappedBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, MaxResponseBodyBytes))
}

// inferContentType guesses a request Content-Type from a parameter body: JSON
// when it looks like a JSON object/array, otherwise form-encoded.
func inferContentType(body string) string {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

var scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)['"]`)
var inlineScriptRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

func extractScriptSrcs(data []byte) []string {
	ms := scriptSrcRe.FindAllSubmatch(data, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m[1]))
	}
	return out
}

func extractInlineScripts(data []byte) []string {
	ms := inlineScriptRe.FindAllSubmatch(data, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m[1]))
	}
	return out
}

var importRe = regexp.MustCompile(`(?m)import\s+(?:[^"']+\s+from\s+)?['"]([^'"\n]+)['"]`)
var dynImportRe = regexp.MustCompile(`(?m)import\(\s*['"]([^'"\n]+)['"]\s*\)`)

func extractJSImports(data []byte) []string {
	uniq := make(map[string]struct{})
	for _, m := range importRe.FindAllSubmatch(data, -1) {
		uniq[string(m[1])] = struct{}{}
	}
	for _, m := range dynImportRe.FindAllSubmatch(data, -1) {
		uniq[string(m[1])] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for v := range uniq {
		out = append(out, v)
	}
	return out
}

func resolveURL(base string, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	u, err := bu.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

func sameScope(baseHost, otherHost string) bool {
	baseHost = strings.TrimPrefix(baseHost, "www.")
	otherHost = strings.TrimPrefix(otherHost, "www.")
	if otherHost == baseHost {
		return true
	}
	return strings.HasSuffix(otherHost, "."+baseHost)
}

func isHTMLContent(urlStr, ct string) bool {
	if strings.Contains(ct, "html") {
		return true
	}
	ext := strings.ToLower(path.Ext(urlStr))
	return ext == ".html" || ext == ".htm"
}

// binaryContentTypes are the exact media types that carry no JavaScript, endpoint
// or secret and so are not worth downloading and scanning. It deliberately omits
// application/octet-stream, which CDNs routinely (mis)apply to real JavaScript and
// JSON, so a mislabelled bundle is never skipped.
var binaryContentTypes = map[string]struct{}{
	"application/pdf": {}, "application/zip": {}, "application/gzip": {},
	"application/x-gzip": {}, "application/x-tar": {}, "application/x-bzip2": {},
	"application/x-rar-compressed": {}, "application/x-7z-compressed": {},
	"application/vnd.ms-fontobject": {}, "application/x-font-ttf": {},
	"application/msword": {}, "application/vnd.ms-excel": {},
	"application/vnd.ms-powerpoint": {},
}

// isBinaryContentType reports whether a response's Content-Type is a binary
// media/asset type worth skipping during a scan. Any image, audio, video or font
// type is skipped by prefix; a curated set of archive and document types is
// skipped exactly. Text, HTML, JavaScript, JSON and XML types — anything that can
// hold a secret or endpoint — are never matched, and neither is the ambiguous
// application/octet-stream. An empty type (server sent none) is never skipped, so
// nothing is dropped merely for lacking a Content-Type.
func isBinaryContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	for _, pre := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(ct, pre) {
			return true
		}
	}
	_, ok := binaryContentTypes[ct]
	return ok
}

// ScanURL scans urlStr and any discovered script or import references.
// Cross-domain resources are followed by default. Set external to false to restrict scanning to the same domain. JavaScript files are scanned using the configured rules.
// ScanURL scans urlStr and any discovered script or import references. When
// endpoints is true, only endpoint matches are returned.
func (e *Extractor) ScanURL(urlStr string, endpoints bool, external bool, render bool) ([]Match, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	visited := make(map[string]struct{})
	return e.scanURL(u.String(), u.Hostname(), endpoints, visited, external, render)
}

// ScanURLPosts scans urlStr and discovered script/import references returning
// only HTTP POST request endpoints found in JavaScript sources.
func (e *Extractor) ScanURLPosts(urlStr string, external bool, render bool) ([]Match, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	visited := make(map[string]struct{})
	return e.scanURLPosts(u.String(), u.Hostname(), visited, external, render)
}

// scanURL performs the recursive scanning used by ScanURL. The baseHost
// parameter indicates the host of the initial URL. The visited map tracks
// already processed URLs to avoid loops. When external is false, only resources
// from the same domain are processed.
func (e *Extractor) scanURL(urlStr, baseHost string, endpoints bool, visited map[string]struct{}, external bool, render bool) ([]Match, error) {
	if _, ok := visited[urlStr]; ok {
		return nil, nil
	}
	visited[urlStr] = struct{}{}

	resp, err := fetchURLResponse(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// A binary asset (image, font, media, archive, document) served under an
	// extensionless or unexpected URL carries no JavaScript, endpoint or secret;
	// skip it before downloading and running every rule over its bytes. Extension
	// filtering already drops most binaries before the fetch — this catches the
	// ones only their Content-Type reveals.
	if isBinaryContentType(resp.Header.Get("Content-Type")) {
		vlog(2, "[scan] skip binary %q at %s", resp.Header.Get("Content-Type"), finalURL)
		return nil, nil
	}

	data, err := readCappedBody(resp.Body)
	if err != nil {
		return nil, err
	}

	var matches []Match

	if isHTMLContent(finalURL, resp.Header.Get("Content-Type")) {
		if e.calibrator != nil && e.calibrator.skipPage(finalURL, resp.StatusCode, data) {
			vlog(1, "[crawl] skip (soft-404/duplicate) %s", finalURL)
			return matches, nil
		}
		if render {
			// Explore application state, not just the initial DOM: scan the seed
			// render and every state exploration reaches through interaction, so a
			// single-page app's event-handler-gated surface is covered too.
			if states, scripts, posts, xhrURLs, err := RenderURLWithStates(finalURL); err == nil && len(states) > 0 {
				for _, p := range posts {
					matches = append(matches, Match{Source: finalURL, Pattern: "post_url", Value: p.URL, Params: p.Body, Severity: "info"})
				}
				// Report the API URLs the page called via XHR/fetch as endpoints.
				// Emitting them as endpoint_url means crawlTargetsFromMatches will
				// fetch and scan them like any other discovered endpoint, so secrets
				// returned only in a dynamically-addressed API response are reached.
				for _, u := range xhrURLs {
					matches = append(matches, Match{Source: finalURL, Pattern: "endpoint_url", Value: u, Severity: "info"})
				}
				for i, st := range states {
					// The captured scripts are the union across states, so they only
					// need scanning once; the visited map dedups regardless.
					var dyn []string
					if i == 0 {
						dyn = scripts
					}
					matches = append(matches, e.scanHTMLState(finalURL, baseHost, st, dyn, endpoints, visited, external, render)...)
				}
				return matches, nil
			}
			// Fall back to a plain render if state exploration failed entirely.
			if rhtml, scripts, err := RenderURL(finalURL); err == nil {
				return append(matches, e.scanHTMLState(finalURL, baseHost, rhtml, scripts, endpoints, visited, external, render)...), nil
			}
		}
		return append(matches, e.scanHTMLState(finalURL, baseHost, data, nil, endpoints, visited, external, render)...), nil
	}

	// treat as JavaScript or other
	reader := bytes.NewReader(data)
	ms, err := e.ScanReaderWithEndpoints(finalURL, reader)
	if err != nil {
		return nil, err
	}
	if endpoints {
		ms = FilterEndpointMatches(ms)
	}
	matches = append(matches, ms...)

	// Recover and scan any original source the bundle advertises via a source
	// map, so secrets and endpoints that only survive in the pre-bundled source
	// are found too.
	if rec := e.recoverSourceMap(finalURL, data, resp.Header, baseHost, external, visited, false); rec != nil {
		if endpoints {
			rec = FilterEndpointMatches(rec)
		}
		matches = append(matches, rec...)
	}

	for _, imp := range extractJSImports(data) {
		abs := resolveURL(finalURL, imp)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if external || sameScope(baseHost, u.Hostname()) {
			vlog(3, "follow import %s (from %s)", u.String(), finalURL)
			ms, err := e.scanURL(u.String(), baseHost, endpoints, visited, external, render)
			if err != nil {
				continue
			}
			matches = append(matches, ms...)
		}
	}
	return matches, nil
}

// scanURLPosts performs recursive scanning like scanURL but returns only POST
// request endpoints.
func (e *Extractor) scanURLPosts(urlStr, baseHost string, visited map[string]struct{}, external bool, render bool) ([]Match, error) {
	if _, ok := visited[urlStr]; ok {
		return nil, nil
	}
	visited[urlStr] = struct{}{}

	resp, err := fetchURLResponse(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// A binary asset (image, font, media, archive, document) served under an
	// extensionless or unexpected URL carries no JavaScript, endpoint or secret;
	// skip it before downloading and running every rule over its bytes. Extension
	// filtering already drops most binaries before the fetch — this catches the
	// ones only their Content-Type reveals.
	if isBinaryContentType(resp.Header.Get("Content-Type")) {
		vlog(2, "[scan] skip binary %q at %s", resp.Header.Get("Content-Type"), finalURL)
		return nil, nil
	}

	data, err := readCappedBody(resp.Body)
	if err != nil {
		return nil, err
	}

	var matches []Match

	if isHTMLContent(finalURL, resp.Header.Get("Content-Type")) {
		if e.calibrator != nil && e.calibrator.skipPage(finalURL, resp.StatusCode, data) {
			vlog(1, "[crawl] skip (soft-404/duplicate) %s", finalURL)
			return matches, nil
		}
		if render {
			// Explore application state so POST endpoints fired only after a
			// client-side navigation or form submission are captured too. The
			// XHR/fetch GET URLs are not emitted here: this path is -posts mode,
			// whose output is intentionally limited to POST request endpoints.
			if states, scripts, posts, _, err := RenderURLWithStates(finalURL); err == nil && len(states) > 0 {
				for _, p := range posts {
					matches = append(matches, Match{Source: finalURL, Pattern: "post_url", Value: p.URL, Params: p.Body, Severity: "info"})
				}
				for i, st := range states {
					var dyn []string
					if i == 0 {
						dyn = scripts
					}
					matches = append(matches, e.scanHTMLStatePosts(finalURL, baseHost, st, dyn, visited, external, render)...)
				}
				return matches, nil
			}
			if rhtml, scripts, err := RenderURL(finalURL); err == nil {
				return append(matches, e.scanHTMLStatePosts(finalURL, baseHost, rhtml, scripts, visited, external, render)...), nil
			}
		}
		return append(matches, e.scanHTMLStatePosts(finalURL, baseHost, data, nil, visited, external, render)...), nil
	}

	reader := bytes.NewReader(data)
	ms, err := e.ScanReaderPostRequests(finalURL, reader)
	if err != nil {
		return nil, err
	}
	matches = append(matches, ms...)

	// Recover POST endpoints from any original source the bundle advertises via
	// a source map.
	if rec := e.recoverSourceMap(finalURL, data, resp.Header, baseHost, external, visited, true); rec != nil {
		matches = append(matches, rec...)
	}

	for _, imp := range extractJSImports(data) {
		abs := resolveURL(finalURL, imp)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if external || sameScope(baseHost, u.Hostname()) {
			ms, err := e.scanURLPosts(u.String(), baseHost, visited, external, render)
			if err != nil {
				continue
			}
			matches = append(matches, ms...)
		}
	}
	return matches, nil
}

// scanHTMLState scans one HTML document reached during a render — the initial
// page or a state exposed only after interaction. It runs the configured rules
// over the document body (unless in safe mode), scans its inline scripts, and
// follows its referenced and dynamically loaded scripts through scanURL. dynamic
// carries script URLs captured during rendering that are not in the static
// markup; it is supplied only for the first state since the render returns the
// union across all states and the visited map dedups the rest.
func (e *Extractor) scanHTMLState(finalURL, baseHost string, data []byte, dynamic []string, endpoints bool, visited map[string]struct{}, external, render bool) []Match {
	var matches []Match
	if !e.safeMode {
		if ms, err := e.ScanReader(finalURL, bytes.NewReader(data)); err == nil {
			matches = append(matches, ms...)
		}
	}
	// Harvest the URLs the page's own markup references (anchors, forms, embedded
	// resources). Without this the crawl would only ever follow links that appear
	// in JavaScript, missing the link graph of server-rendered and multi-page
	// sites entirely.
	matches = append(matches, extractHTMLLinkMatches(data, finalURL)...)
	for _, src := range extractInlineScripts(data) {
		ms, err := e.ScanReaderWithEndpoints("inline.js", bytes.NewReader([]byte(src)))
		if err == nil {
			if endpoints {
				ms = FilterEndpointMatches(ms)
			}
			matches = append(matches, ms...)
		}
	}
	base := documentBase(data, finalURL)
	sources := extractScriptSrcs(data)
	sources = append(sources, dynamic...)
	for _, src := range sources {
		abs := resolveURL(base, src)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if external || sameScope(baseHost, u.Hostname()) {
			ms, err := e.scanURL(u.String(), baseHost, endpoints, visited, external, render)
			if err != nil {
				continue
			}
			matches = append(matches, ms...)
		}
	}
	return matches
}

// scanHTMLStatePosts scans one HTML document reached during a render for POST
// endpoints, following its referenced and dynamically loaded scripts through
// scanURLPosts. Like scanHTMLState, dynamic is supplied only for the first
// state. It mirrors the POST-only behaviour of scanURLPosts: inline scripts are
// not scanned here (POST endpoints come from the linked script sources).
func (e *Extractor) scanHTMLStatePosts(finalURL, baseHost string, data []byte, dynamic []string, visited map[string]struct{}, external, render bool) []Match {
	var matches []Match
	// During a crawl (calibrator set), harvest the page's markup links so the posts
	// crawl follows the HTML link graph to reach deeper pages — and the POST
	// endpoints their scripts hold — that nothing in JavaScript references. These
	// endpoint_url matches drive navigation only; the CLI filters them out of the
	// POST-endpoint output via FilterPostMatches.
	if e.calibrator != nil {
		matches = append(matches, extractHTMLLinkMatches(data, finalURL)...)
	}
	base := documentBase(data, finalURL)
	sources := extractScriptSrcs(data)
	sources = append(sources, dynamic...)
	for _, src := range sources {
		abs := resolveURL(base, src)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if external || sameScope(baseHost, u.Hostname()) {
			ms, err := e.scanURLPosts(u.String(), baseHost, visited, external, render)
			if err != nil {
				continue
			}
			matches = append(matches, ms...)
		}
	}
	return matches
}
