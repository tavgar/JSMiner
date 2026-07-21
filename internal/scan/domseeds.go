package scan

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var domAPIRouteRe = regexp.MustCompile(`(?i)(?:^|/)(?:api|graphql|gql|rest|rpc|v[0-9]+)(?:/|$)`)

// DOMSeedURLsFromMatches turns routes found by the static/rendered crawl into
// browser instrumentation seeds. It keeps query names, drops fragments and
// obvious non-document assets, and respects the original target scope.
func DOMSeedURLsFromMatches(seed string, matches []Match, allowExternal bool, max int) []string {
	seedURL, err := url.Parse(seed)
	if err != nil || seedURL.Hostname() == "" {
		return nil
	}
	seen := map[string]struct{}{normalizeDOMSeed(seedURL): {}}
	var out []string
	for _, match := range matches {
		switch match.Pattern {
		case GatheredURLPattern, "endpoint_url", "endpoint_path":
		default:
			continue
		}
		raw := strings.TrimSpace(match.Value)
		if raw == "" {
			continue
		}
		// Browser request paths are resolved against the document, not the bundle
		// URL that happened to contain the string. Rooted/relative endpoint_path
		// matches therefore use the original application seed as their base.
		candidate, err := seedURL.Parse(raw)
		if err != nil || (candidate.Scheme != "http" && candidate.Scheme != "https") || candidate.Hostname() == "" {
			continue
		}
		if !allowExternal && !sameScope(seedURL.Hostname(), candidate.Hostname()) {
			continue
		}
		if !isDOMDocumentCandidate(candidate) {
			continue
		}
		candidate.Fragment = ""
		norm := normalizeDOMSeed(candidate)
		if _, exists := seen[norm]; exists {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func normalizeDOMSeed(u *url.URL) string {
	copyURL := *u
	copyURL.Fragment = ""
	if copyURL.Path == "" {
		copyURL.Path = "/"
	}
	return copyURL.String()
}

func isDOMDocumentCandidate(u *url.URL) bool {
	// Extensionless API routes are common endpoint discoveries but are not browser
	// documents. Rendering them repeats a request the crawl already made and often
	// just opens Chrome's JSON viewer. Keep the heuristic deliberately narrow so
	// ordinary extensionless application routes remain eligible.
	if domAPIRouteRe.MatchString(u.Path) {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	if ext == "" {
		return true
	}
	switch ext {
	case ".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp", ".do", ".action":
		return true
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map", ".css", ".xml", ".txt",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
		".pdf", ".zip", ".gz", ".tar", ".mp3", ".mp4", ".webm", ".wasm":
		return false
	default:
		// Unknown server-side extensions can still produce documents.
		return true
	}
}
