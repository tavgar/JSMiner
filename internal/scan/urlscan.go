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
	"time"
)

// newHTTPClient builds the HTTP client shared by the URL fetch helpers: a cloned
// default transport that optionally skips TLS verification, a request timeout and
// a redirect cap.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if SkipTLSVerification {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
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
	return newHTTPClient().Do(req)
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var matches []Match

	if isHTMLContent(finalURL, resp.Header.Get("Content-Type")) {
		if e.calibrator != nil && e.calibrator.skipPage(finalURL, resp.StatusCode, data) {
			return matches, nil
		}
		var dynamic []string
		if render {
			if rhtml, scripts, posts, err := RenderURLWithRequests(finalURL); err == nil {
				data = rhtml
				dynamic = scripts
				for _, p := range posts {
					matches = append(matches, Match{Source: finalURL, Pattern: "post_url", Value: p.URL, Params: p.Body, Severity: "info"})
				}
			} else if rhtml, scripts, err := RenderURL(finalURL); err == nil {
				data = rhtml
				dynamic = scripts
			}
		}
		if !e.safeMode {
			ms, err := e.ScanReader(finalURL, bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			matches = append(matches, ms...)
		}
		sources := extractScriptSrcs(data)
		sources = append(sources, dynamic...)
		inline := extractInlineScripts(data)
		for _, src := range inline {
			ms, err := e.ScanReaderWithEndpoints("inline.js", bytes.NewReader([]byte(src)))
			if err == nil {
				if endpoints {
					ms = FilterEndpointMatches(ms)
				}
				matches = append(matches, ms...)
			}
		}
		for _, src := range sources {
			abs := resolveURL(finalURL, src)
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
		return matches, nil
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var matches []Match

	if isHTMLContent(finalURL, resp.Header.Get("Content-Type")) {
		if e.calibrator != nil && e.calibrator.skipPage(finalURL, resp.StatusCode, data) {
			return matches, nil
		}
		var dynamic []string
		if render {
			if rhtml, scripts, posts, err := RenderURLWithRequests(finalURL); err == nil {
				data = rhtml
				dynamic = scripts
				for _, p := range posts {
					matches = append(matches, Match{Source: finalURL, Pattern: "post_url", Value: p.URL, Params: p.Body, Severity: "info"})
				}
			} else if rhtml, scripts, err := RenderURL(finalURL); err == nil {
				data = rhtml
				dynamic = scripts
			}
		}
		sources := extractScriptSrcs(data)
		sources = append(sources, dynamic...)
		for _, src := range sources {
			abs := resolveURL(finalURL, src)
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
		return matches, nil
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
