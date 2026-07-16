package scan

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Web Linking (RFC 8288) lets a server advertise related resources in a `Link`
// response header — `Link: <https://api.example.com/orders?page=2>; rel="next"`
// — rather than in the body. It is the dominant pagination mechanism for
// header-driven REST APIs (GitHub's, among many), so a crawl that reads only the
// body's JSON `_links` misses the next/related pages entirely. extractLinkHeaderMatches
// recovers those references and emits them as ordinary endpoint matches, so the
// crawl follows them like any other discovered URL.

// linkHeaderEntryRe splits a Link header into its comma-separated entries: a
// `<target-uri>` followed by its `; key=value` parameters, consumed up to the next
// entry. The URI is group 1 and the raw parameter string is group 2. Splitting on
// the angle-bracketed target rather than on commas is what keeps a comma inside a
// URL (common in query strings) from fracturing an entry.
var linkHeaderEntryRe = regexp.MustCompile(`<([^>]+)>((?:\s*;\s*[^;,]+)*)`)

// linkRelRe pulls the rel value out of a Link entry's parameters, quoted or bare.
var linkRelRe = regexp.MustCompile(`(?i)\brel\s*=\s*(?:"([^"]*)"|([^;,\s]+))`)

// nonNavLinkRels are Web-Linking relation types that point at assets or browser
// hints rather than a navigable resource, so an entry carrying one is not followed.
// self and canonical name the current resource, so they add nothing to the crawl.
var nonNavLinkRels = map[string]struct{}{
	"stylesheet": {}, "icon": {}, "shortcut": {}, "apple-touch-icon": {},
	"mask-icon": {}, "manifest": {}, "preload": {}, "prefetch": {},
	"dns-prefetch": {}, "preconnect": {}, "modulepreload": {}, "prerender": {},
	"pingback": {}, "self": {}, "canonical": {},
}

// extractLinkHeaderMatches returns the navigable URLs advertised in a response's
// `Link` headers, resolved against pageURL and emitted as endpoint_url matches.
// Entries whose every rel is a non-navigational asset/hint relation (see
// nonNavLinkRels) are skipped; an entry with no rel at all is still followed, since
// a bare `Link: <…>` is a reference worth reaching.
func extractLinkHeaderMatches(header http.Header, pageURL string) []Match {
	if header == nil {
		return nil
	}
	values := header.Values("Link")
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []Match
	for _, v := range values {
		for _, m := range linkHeaderEntryRe.FindAllStringSubmatch(v, -1) {
			ref := strings.TrimSpace(m[1])
			if ref == "" || isTemplatePlaceholder(ref) {
				continue
			}
			if !linkRelNavigable(m[2]) {
				continue
			}
			abs := resolveURL(pageURL, ref)
			u, err := url.Parse(abs)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			u.Fragment = ""
			norm := u.String()
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, Match{Source: pageURL, Pattern: "endpoint_url", Value: norm, Severity: "info"})
		}
	}
	return out
}

// linkRelNavigable reports whether a Link entry's parameter string names a
// relation worth following. An entry with no rel is navigable (a bare reference);
// an entry whose rel tokens are all non-navigational (stylesheet, preload, self, …)
// is not. A rel may carry several space-separated tokens; the entry is followed
// unless every token is non-navigational.
func linkRelNavigable(params string) bool {
	m := linkRelRe.FindStringSubmatch(params)
	if m == nil {
		return true
	}
	rel := m[1]
	if rel == "" {
		rel = m[2]
	}
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return true
	}
	for _, tok := range strings.Fields(strings.ToLower(rel)) {
		if _, blocked := nonNavLinkRels[tok]; !blocked {
			return true
		}
	}
	return false
}
