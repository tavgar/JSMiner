package scan

import (
	"io"
	"sort"
	"strings"
)

// GatheredURLPattern is the Match.Pattern used for the crawler's "gathered URL"
// findings: in-scope URLs the crawl confirmed as live, annotated with the HTTP
// request methods that worked against them (and, for parameter replay, the
// parameters that produced the hit). They are surfaced as their own segment in
// the output, beneath the normal JavaScript findings.
const GatheredURLPattern = "gathered_url"

// bodyMethods are the request verbs a discovered parameter body is replayed with;
// GET/DELETE/OPTIONS carry no meaningful body for this purpose.
var bodyMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

// defaultRequestMethods is the set of HTTP methods the crawler probes every
// in-scope target with by default, so a report can state which verbs each URL
// actually accepts rather than assuming GET.
func defaultRequestMethods() []string {
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
}

// normalizeMethods upper-cases, de-duplicates and orders a caller-supplied method
// list, falling back to the default set when it is empty. GET is always probed
// first so the most common verb is reported first.
func normalizeMethods(in []string) []string {
	if len(in) == 0 {
		return defaultRequestMethods()
	}
	seen := make(map[string]struct{})
	var out []string
	for _, m := range in {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	if len(out) == 0 {
		return defaultRequestMethods()
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i] == "GET" {
			return true
		}
		if out[j] == "GET" {
			return false
		}
		return false
	})
	return out
}

// methodWorks decides whether a response means the method is genuinely handled by
// the URL. A response counts as "working" only when its status is non-error
// (2xx/3xx) and it does not match the level's learned catch-all/error fingerprint
// for that verb — that fingerprint is the per-request-type error logic. A 405/501
// is always treated as not working regardless of calibration.
func methodWorks(cal *autoCalibrator, method, pageURL string, status int, body []byte) bool {
	if status == 405 || status == 501 {
		return false
	}
	if status < 200 || status >= 400 {
		return false
	}
	if cal != nil && cal.methodCatchAll(method, pageURL, status, body) {
		return false
	}
	return true
}

// probeURLMethods requests pageURL with each method and returns the ordered list
// of methods that worked (see methodWorks). body, when non-empty, is sent with
// the body-bearing verbs so discovered parameters can be replayed. It performs
// one request per method; the crawl's page budget bounds how often it is called.
func probeURLMethods(cal *autoCalibrator, pageURL string, methods []string, body string) []string {
	var worked []string
	for _, m := range methods {
		reqBody := ""
		if body != "" && bodyMethods[m] {
			reqBody = body
		}
		resp, err := fetchURLResponseMethod(pageURL, m, reqBody)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if methodWorks(cal, m, pageURL, resp.StatusCode, data) {
			worked = append(worked, m)
		}
	}
	return worked
}

// gatheredMatch builds a gathered-URL finding for pageURL from the methods that
// worked, optionally recording the replayed parameters. It returns ok=false when
// no method worked, so the caller can drop dead URLs.
func gatheredMatch(pageURL string, worked []string, params string) (Match, bool) {
	if len(worked) == 0 {
		return Match{}, false
	}
	p := "methods=" + strings.Join(worked, ",")
	if params != "" {
		p += " params=" + params
	}
	return Match{Source: pageURL, Pattern: GatheredURLPattern, Value: pageURL, Params: p, Severity: "info"}, true
}

// paramReplayer implements "try every discovered parameter at every discovered
// level": it accumulates the parameter bodies seen anywhere in the crawl and the
// directory levels seen anywhere in the crawl, and yields each (level, param)
// pairing exactly once so the crawler can replay the params against that level.
// Whether a replay counts as a hit is decided by the level's own per-method
// calibration, keeping results specific to each level's learned error logic.
//
// Generation is incremental — a parameter discovered late still pairs with levels
// seen earlier and vice versa — and bounded by max so the params×levels product
// cannot run away.
type paramReplayer struct {
	origin string // scheme://host of the seed, no trailing slash
	max    int    // cap on generated (level, param) replays (0 = unlimited)

	params   []string
	paramSet map[string]struct{}
	levels   []string
	lvlSet   map[string]struct{}

	generated int
}

// replayTarget is a single (level URL, parameter body) pairing to replay.
type replayTarget struct {
	url    string
	params string
}

func newParamReplayer(origin string, max int) *paramReplayer {
	return &paramReplayer{
		origin:   strings.TrimSuffix(origin, "/"),
		max:      max,
		paramSet: make(map[string]struct{}),
		lvlSet:   make(map[string]struct{}),
	}
}

// observe folds fresh parameter bodies and directory levels into the accumulated
// sets and returns the new (level, param) pairings to replay. New params pair
// with previously known levels; new levels pair with every known param. Each
// pairing is produced once and counted against the cap.
func (p *paramReplayer) observe(newParams, targetURLs []string) []replayTarget {
	if p.max > 0 && p.generated >= p.max {
		return nil
	}

	oldLevels := p.levels

	var freshParams []string
	for _, prm := range newParams {
		prm = strings.TrimSpace(prm)
		if prm == "" {
			continue
		}
		if _, ok := p.paramSet[prm]; ok {
			continue
		}
		p.paramSet[prm] = struct{}{}
		p.params = append(p.params, prm)
		freshParams = append(freshParams, prm)
	}

	var freshLevels []string
	for _, raw := range targetURLs {
		for _, lvl := range levelsWithAncestors(raw) {
			if _, ok := p.lvlSet[lvl]; ok {
				continue
			}
			p.lvlSet[lvl] = struct{}{}
			p.levels = append(p.levels, lvl)
			freshLevels = append(freshLevels, lvl)
		}
	}

	var out []replayTarget
	emit := func(lvl, prm string) bool {
		out = append(out, replayTarget{url: p.origin + lvl, params: prm})
		p.generated++
		return p.max > 0 && p.generated >= p.max
	}
	// fresh params × already-known levels
	for _, prm := range freshParams {
		for _, lvl := range oldLevels {
			if emit(lvl, prm) {
				return out
			}
		}
	}
	// fresh levels × all params (old + new)
	for _, lvl := range freshLevels {
		for _, prm := range p.params {
			if emit(lvl, prm) {
				return out
			}
		}
	}
	return out
}

// paramsFromMatches collects the distinct, non-empty parameter bodies carried by
// POST/PUT/PATCH endpoint matches on a page, for replay across levels.
func paramsFromMatches(ms []Match) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range ms {
		switch m.Pattern {
		case "post_url", "post_path", "put_url", "put_path", "patch_url", "patch_path":
		default:
			continue
		}
		prm := strings.TrimSpace(m.Params)
		if prm == "" {
			continue
		}
		if _, ok := seen[prm]; ok {
			continue
		}
		seen[prm] = struct{}{}
		out = append(out, prm)
	}
	return out
}

// FilterGatheredMatches returns only the gathered-URL findings from ms, preserving
// order. It lets the CLI keep the gathered-URL segment when the endpoint-only
// filter would otherwise drop it.
func FilterGatheredMatches(ms []Match) []Match {
	var out []Match
	for _, m := range ms {
		if m.Pattern == GatheredURLPattern {
			out = append(out, m)
		}
	}
	return out
}
