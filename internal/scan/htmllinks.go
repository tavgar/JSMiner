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
	for _, m := range htmlURLAttrRe.FindAllSubmatch(data, -1) {
		raw := decodeXMLEntities(strings.TrimSpace(string(m[1])))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		low := strings.ToLower(raw)
		skip := false
		for _, s := range nonNavSchemes {
			if strings.HasPrefix(low, s) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		abs := resolveURL(pageURL, raw)
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
	return out
}
