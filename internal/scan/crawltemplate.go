package scan

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// defaultTemplateSampleMax is how many representatives of each template class a
// crawl keeps when template deduplication is on but no explicit cap is given. A
// handful is enough to notice a class while still catching the odd instance
// whose data (and therefore its secrets) differs from its siblings.
const defaultTemplateSampleMax = 3

// templateClasser recognises templated duplicate pages by their URL shape and
// caps how many of each class a crawl fetches. Many sites expose the same page
// template over an unbounded key space — /product/1, /product/2, …; ?page=1,
// ?page=2, …; calendar and faceted URLs that differ only in a date or filter —
// and fetching every instance burns the page budget on structurally identical
// copies. The classer folds each candidate URL to a template key (see
// urlTemplateKey) and admits only the first `max` URLs of each key, so the crawl
// spends its budget on genuinely distinct pages instead.
//
// It runs at enqueue time, before a URL is fetched, so a suppressed instance
// costs neither a request nor a slot in the page budget. Structurally identical
// pages whose URLs do not reveal the pattern (e.g. slug-keyed pages) are caught
// later, post-fetch, by the structural body signature in autoCalibrator.
type templateClasser struct {
	max    int            // representatives kept per class (<= 0 disables the cap)
	counts map[string]int // template key -> representatives admitted so far
}

func newTemplateClasser(max int) *templateClasser {
	return &templateClasser{max: max, counts: make(map[string]int)}
}

// admit reports whether rawURL may still be crawled. It returns true — and
// records the URL as a representative of its class — while the class has fewer
// than max members, and false once the class is full. A nil classer or a
// non-positive max admits everything, so callers can stay unconditional.
func (tc *templateClasser) admit(rawURL string) bool {
	if tc == nil || tc.max <= 0 {
		return true
	}
	key := urlTemplateKey(rawURL)
	if tc.counts[key] >= tc.max {
		return false
	}
	tc.counts[key]++
	return true
}

var (
	// allDigitsSeg matches a path segment that is purely numeric (an id or index).
	allDigitsSeg = regexp.MustCompile(`^\d+$`)
	// uuidSeg matches a canonical UUID.
	uuidSeg = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// dateSeg matches a year, year-month or year-month-day segment (calendar URLs).
	dateSeg = regexp.MustCompile(`^\d{4}([-/]\d{1,2}){0,2}$`)
	// hexIDSeg matches a long hexadecimal token (a hash or opaque id).
	hexIDSeg = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
)

// urlTemplateKey folds rawURL to the key that identifies its page template.
// Data-carrying path segments (numeric ids, UUIDs, dates, hashes and long
// mixed-alphanumeric ids) are replaced with a placeholder so /product/1 and
// /product/2 share a key, while route segments such as "product" or "v2" are
// preserved so distinct pages stay distinct. Query strings are reduced to their
// sorted parameter names with the values dropped, so ?page=1 and ?page=2 — and
// faceted URLs differing only in filter values — collapse to one key too.
func urlTemplateKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if variableSegment(s) {
			segs[i] = "{}"
		}
	}
	key := u.Host + strings.Join(segs, "/")
	if u.RawQuery != "" {
		names := make([]string, 0, len(u.Query()))
		for name := range u.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		key += "?" + strings.Join(names, "&")
	}
	return key
}

// variableSegment reports whether a path segment looks like data (an id, date,
// hash or opaque token) rather than a fixed route name. Short mixed tokens such
// as "p0", "v2" or "api" are treated as route names and kept, so genuinely
// different sections are never merged; only clearly data-like segments generalise.
func variableSegment(s string) bool {
	if s == "" {
		return false
	}
	switch {
	case allDigitsSeg.MatchString(s), uuidSeg.MatchString(s),
		dateSeg.MatchString(s), hexIDSeg.MatchString(s):
		return true
	}
	// Long tokens carrying a digit are far more likely to be ids or slugs than
	// route names; the length floor keeps short versioned routes ("v2", "p0")
	// distinct.
	return len(s) >= 12 && containsDigit(s)
}

func containsDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}
