package scan

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// fetchURLResponse retrieves a URL and returns the http.Response
// with limited redirects and a default User-Agent.
func fetchURLResponse(u string) (*http.Response, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	return client.Do(req)
}

var scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)['"]`)

func extractScriptSrcs(data []byte) []string {
	ms := scriptSrcRe.FindAllSubmatch(data, -1)
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
		var dynamic []string
		if render {
			if rhtml, scripts, err := RenderURL(finalURL); err == nil {
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
