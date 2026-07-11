package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Source-map recovery lets the crawler scan the original, pre-bundled source
// that a minified JavaScript bundle advertises via a source map. Production
// bundles are minified/transpiled, so many secrets and endpoints only survive
// in a readable form in the original source — which is frequently still shipped
// alongside the bundle. When enabled (the default), a scanned JS bundle is
// inspected for a `//# sourceMappingURL=` / `//@ sourceMappingURL=` comment or a
// `SourceMap:`/`X-SourceMap:` response header; the referenced map is recovered
// (from a `data:` URI or by fetching it) and each original source it carries is
// scanned through the normal rules, so its findings flow up as ordinary Matches.

// maxSourceMapBytes caps the size of a fetched source map or original source
// file. Reusing MaxBufferSize keeps recovered sources within the same ceiling
// the line scanner already tolerates for large bundles.
const maxSourceMapBytes = MaxBufferSize

// maxRecoveredSources bounds how many original sources a single map may expand
// to, protecting against pathological maps with tens of thousands of entries.
const maxRecoveredSources = 5000

// sourceMapRefRe captures the reference that follows a sourceMappingURL
// annotation, in either the `//#`/`//@` line-comment or `/*# ... */` block form.
// The value runs up to the first whitespace or quote; a trailing `*/` from a
// block comment is stripped by the caller.
var sourceMapRefRe = regexp.MustCompile(`sourceMappingURL=([^\s'"]+)`)

// sourceMap is the subset of the Source Map v3 format needed to recover original
// source: the source paths, their optionally-embedded contents, and a root that
// the paths resolve against. Mappings/VLQ are irrelevant to scanning and ignored.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	SourceRoot     string   `json:"sourceRoot"`
}

// sourceMapReference returns the source-map reference advertised for a bundle,
// or "" if none. A `SourceMap`/`X-SourceMap` response header takes precedence
// over an in-body comment (matching DevTools); when both are absent the last
// sourceMappingURL comment in the body wins, per the spec.
func sourceMapReference(data []byte, header http.Header) string {
	if header != nil {
		if v := strings.TrimSpace(header.Get("SourceMap")); v != "" {
			return v
		}
		if v := strings.TrimSpace(header.Get("X-SourceMap")); v != "" {
			return v
		}
	}
	// Cheap byte scan before the regex: the vast majority of bundles carry no
	// annotation, and this avoids a regex pass over multi-MB minified inputs.
	if !bytes.Contains(data, []byte("sourceMappingURL")) {
		return ""
	}
	m := sourceMapRefRe.FindAllSubmatch(data, -1)
	if len(m) == 0 {
		return ""
	}
	ref := strings.TrimSpace(string(m[len(m)-1][1]))
	ref = strings.TrimSuffix(ref, "*/")
	return strings.TrimSpace(ref)
}

// recoverSourceMap discovers the source map advertised by a JS bundle and scans
// every original source it carries, returning the matches. bundleURL is the
// bundle's final URL, header its response headers, and visited the shared
// fetch-dedup set. posts selects POST-endpoint scanning over secret/endpoint
// scanning. It is a no-op (nil) when recovery is disabled or no map is found.
func (e *Extractor) recoverSourceMap(bundleURL string, data []byte, header http.Header, baseHost string, external bool, visited map[string]struct{}, posts bool) []Match {
	if !e.recoverSourceMaps {
		return nil
	}
	ref := sourceMapReference(data, header)
	if ref == "" {
		return nil
	}
	raw, mapURL, ok := e.loadSourceMap(ref, bundleURL, baseHost, external, visited)
	if !ok {
		return nil
	}
	var sm sourceMap
	if err := json.Unmarshal(raw, &sm); err != nil {
		return nil
	}

	var matches []Match
	scanned := 0
	for i, src := range sm.Sources {
		if scanned >= maxRecoveredSources {
			break
		}
		var body []byte
		if i < len(sm.SourcesContent) && sm.SourcesContent[i] != "" {
			body = []byte(sm.SourcesContent[i])
		} else {
			// No embedded content: fetch the original only when it resolves to an
			// in-scope http(s) URL. Virtual paths (webpack://, ng://, …) are not
			// fetchable and fall out at the scheme check.
			body = e.fetchOriginalSource(mapURL, sm.SourceRoot, src, baseHost, external, visited)
			if body == nil {
				continue
			}
		}
		ms, err := e.scanRecoveredSource(sourceLabel(src), body, posts)
		if err != nil {
			continue
		}
		matches = append(matches, ms...)
		scanned++
	}
	return matches
}

// loadSourceMap resolves a source-map reference to its raw JSON bytes and the
// URL the map was loaded from (used to resolve non-embedded originals). It
// decodes `data:` URIs inline and otherwise fetches the map, honoring scope and
// recording the URL in visited so a map shared by several bundles is fetched
// once. For a data: URI the map URL is the bundle URL, since embedded relative
// sources resolve against the bundle's location.
func (e *Extractor) loadSourceMap(ref, bundleURL, baseHost string, external bool, visited map[string]struct{}) ([]byte, string, bool) {
	if strings.HasPrefix(ref, "data:") {
		raw, ok := decodeDataURI(ref)
		return raw, bundleURL, ok
	}
	abs := resolveURL(bundleURL, ref)
	raw, ok := e.fetchInScope(abs, baseHost, external, visited)
	return raw, abs, ok
}

// fetchOriginalSource fetches the original source for a map entry when it is not
// embedded. src is resolved against sourceRoot and the map URL; only in-scope
// http(s) URLs are fetched. Returns nil when the source is not fetchable.
func (e *Extractor) fetchOriginalSource(mapURL, sourceRoot, src, baseHost string, external bool, visited map[string]struct{}) []byte {
	abs := resolveURL(mapURL, joinSourceRoot(sourceRoot, src))
	raw, ok := e.fetchInScope(abs, baseHost, external, visited)
	if !ok {
		return nil
	}
	return raw
}

// fetchInScope GETs abs when it is an http(s) URL within scope and not already
// visited, returning the body (capped at maxSourceMapBytes). It shares the
// crawl's fetch dedup so each URL is retrieved at most once.
func (e *Extractor) fetchInScope(abs, baseHost string, external bool, visited map[string]struct{}) ([]byte, bool) {
	u, err := url.Parse(abs)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false
	}
	if !external && !sameScope(baseHost, u.Hostname()) {
		return nil, false
	}
	if _, ok := visited[abs]; ok {
		return nil, false
	}
	visited[abs] = struct{}{}
	resp, err := fetchURLResponse(abs)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceMapBytes))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// decodeDataURI decodes a `data:` URI carrying a source map. It handles the
// `;base64,` form as well as plain (optionally percent-encoded) payloads.
func decodeDataURI(uri string) ([]byte, bool) {
	rest := strings.TrimPrefix(uri, "data:")
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return nil, false
	}
	meta, payload := rest[:comma], rest[comma+1:]
	if strings.Contains(meta, "base64") {
		if dec, err := base64.StdEncoding.DecodeString(payload); err == nil {
			return dec, true
		}
		if dec, err := base64.RawStdEncoding.DecodeString(payload); err == nil {
			return dec, true
		}
		return nil, false
	}
	if s, err := url.QueryUnescape(payload); err == nil {
		return []byte(s), true
	}
	return []byte(payload), true
}

// joinSourceRoot combines a sourceRoot with a source path using a single
// separator, so the result can be resolved against the map URL.
func joinSourceRoot(root, src string) string {
	if root == "" {
		return src
	}
	if strings.HasSuffix(root, "/") {
		return root + src
	}
	return root + "/" + src
}

// sourceLabel produces the attribution shown for a recovered source. The raw
// map path (e.g. "webpack:///src/app.js") is kept as-is after trimming so the
// finding points back at the original file.
func sourceLabel(src string) string {
	return strings.TrimSpace(src)
}

// scanRecoveredSource scans recovered original source through the normal scan
// path, attributing every finding to label. Recovered content is definitively
// JavaScript/TypeScript, but the endpoint and safe-mode gates key off the
// source name's extension; when label is not recognized as JS, a JS-recognized
// name is used for the scan so those rules still fire, and the faithful label is
// restored on each match afterward.
func (e *Extractor) scanRecoveredSource(label string, data []byte, posts bool) ([]Match, error) {
	scanName := label
	if scanName != "stdin" && !isJSFile(scanName) {
		scanName = "recovered.js"
	}
	var (
		ms  []Match
		err error
	)
	if posts {
		ms, err = e.ScanReaderPostRequests(scanName, bytes.NewReader(data))
	} else {
		ms, err = e.ScanReaderWithEndpoints(scanName, bytes.NewReader(data))
	}
	if err != nil {
		return nil, err
	}
	for i := range ms {
		ms[i].Source = label
	}
	return ms, nil
}
