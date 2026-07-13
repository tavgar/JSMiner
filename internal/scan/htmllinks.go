package scan

import (
	"net/url"
	"regexp"
	"strings"
)

// htmlURLAttrRe captures the value of the URL-bearing HTML attributes a page uses
// to reference other resources: anchor/link targets (href), embedded resources
// (src), form submission targets (action/formaction) and the common data-url /
// data-href hooks single-page routers read. Only quoted values are matched, which
// is how these attributes appear in practice and keeps the pattern precise.
var htmlURLAttrRe = regexp.MustCompile(`(?is)\b(?:href|src|action|formaction|data-url|data-href|data-src)\s*=\s*["']([^"'>\s]+)["']`)

// nonNavSchemes are URL schemes that carry no crawlable/scannable resource, so a
// link using one is skipped rather than emitted as an endpoint.
var nonNavSchemes = []string{"javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "sms:", "callto:"}

// metaTagRe matches a single <meta> tag, and metaRefreshURLRe pulls the redirect
// target out of a refresh directive's content ("<seconds>; url=<target>").
var metaTagRe = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
var metaRefreshURLRe = regexp.MustCompile(`(?is)content\s*=\s*["'][^"']*?\burl\s*=\s*([^"'\s;]+)`)
var metaIsRefreshRe = regexp.MustCompile(`(?is)http-equiv\s*=\s*["']?\s*refresh\b`)

// isTemplatePlaceholder reports whether a raw attribute value is a server- or
// client-side template expression rather than a real URL. Template engines leave
// markers like {{id}}, ${base}, <%= x %> or #{path} in href/src attributes; the
// characters { } < > are never valid unencoded in a genuine URL, so their
// presence marks the value as a placeholder to skip instead of resolving into a
// garbage endpoint.
func isTemplatePlaceholder(raw string) bool {
	return strings.ContainsAny(raw, "{}<>")
}

// extractHTMLLinkMatches finds the URLs referenced by a page's HTML markup and
// returns them as resolved, absolute endpoint matches. The crawler otherwise
// discovers URLs only from JavaScript, so on a server-rendered or multi-page site
// its <a href> / <form action> links — the primary way such pages reach one
// another — would be invisible. Each value is entity-decoded and resolved against
// the page URL, so relative links (including bare-relative ones the JS endpoint
// heuristics reject) become concrete, crawlable URLs.
func extractHTMLLinkMatches(data []byte, pageURL string) []Match {
	seen := make(map[string]struct{})
	var out []Match
	emit := func(rawAttr string) {
		raw := decodeXMLEntities(strings.TrimSpace(rawAttr))
		if raw == "" || strings.HasPrefix(raw, "#") || isTemplatePlaceholder(raw) {
			return
		}
		low := strings.ToLower(raw)
		for _, s := range nonNavSchemes {
			if strings.HasPrefix(low, s) {
				return
			}
		}
		abs := resolveURL(pageURL, raw)
		u, err := url.Parse(abs)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		norm := u.String()
		if _, ok := seen[norm]; ok {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, Match{Source: pageURL, Pattern: "endpoint_url", Value: norm, Severity: "info"})
	}

	for _, m := range htmlURLAttrRe.FindAllSubmatch(data, -1) {
		emit(string(m[1]))
	}
	// A meta refresh (<meta http-equiv="refresh" content="0; url=...">) is a real
	// navigation the crawl should follow, so pull its target out too.
	for _, tag := range metaTagRe.FindAll(data, -1) {
		if !metaIsRefreshRe.Match(tag) {
			continue
		}
		if u := metaRefreshURLRe.FindSubmatch(tag); u != nil {
			emit(string(u[1]))
		}
	}
	return out
}
