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
// the body-bearing verbs. It performs one request per method; the crawl's page
// budget bounds how often it is called.
//
// A GET baseline is used to suppress the "every verb works" noise that permissive
// servers produce. Many hosts — CDNs, edge gateways, static-file servers — return
// the resource (a non-error, non-catch-all response) for whatever method they are
// sent, so a plain per-verb check reports GET,POST,PUT,PATCH,DELETE,OPTIONS on a
// static .js file or a landing page even though only GET is genuinely handled.
// When GET works on the URL, another verb is therefore reported only if its
// response differs from the GET baseline (coarse status|words|lines signature): a
// verb that echoes the GET response is the server ignoring the method, not a
// distinct operation. OPTIONS is dropped outright in that case as a CORS
// preflight artifact. When GET does not work (a real POST-only API rejects GET
// with 404/405), there is no baseline to collapse against, so every working verb
// is reported as before — keeping genuine per-route method constraints intact.
type probeResult struct {
	method string
	works  bool
	sig    string
}

// methodProbeBaseline is the GET response the page scanner already fetched.
// Reusing it during method probing avoids downloading every crawled URL twice
// while preserving the exact status/body checks probeURLMethods applies.
type methodProbeBaseline struct {
	status int
	body   []byte
}

func probeURLMethodsWithBaseline(cal *autoCalibrator, pageURL string, methods []string, body string, baseline *methodProbeBaseline) []string {
	probes := make([]probeResult, 0, len(methods))
	for _, m := range methods {
		reqBody := ""
		if body != "" && bodyMethods[m] {
			reqBody = body
		}
		if m == "GET" && reqBody == "" && baseline != nil {
			probes = append(probes, probeResult{
				method: m,
				works:  methodWorks(cal, m, pageURL, baseline.status, baseline.body),
				sig:    pageSig(baseline.status, baseline.body),
			})
			continue
		}
		resp, err := fetchURLResponseMethodSameScope(pageURL, m, reqBody)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		probes = append(probes, probeResult{
			method: m,
			works:  methodWorks(cal, m, pageURL, resp.StatusCode, data),
			sig:    pageSig(resp.StatusCode, data),
		})
	}

	// Establish the GET baseline: whether GET is genuinely handled, and what its
	// response looks like.
	getWorks := false
	getSig := ""
	for _, pr := range probes {
		if pr.method == "GET" {
			getWorks = pr.works
			getSig = pr.sig
			break
		}
	}

	var worked []string
	for _, pr := range probes {
		if !pr.works {
			continue
		}
		if getWorks && pr.method != "GET" {
			// The resource already answers GET, so collapse method-agnostic verbs.
			if pr.method == "OPTIONS" {
				continue // CORS preflight, never a real operation
			}
			if pr.sig == getSig {
				continue // same response as GET: the server is ignoring the method
			}
		}
		worked = append(worked, pr.method)
	}
	return worked
}

func probeURLMethods(cal *autoCalibrator, pageURL string, methods []string, body string) []string {
	return probeURLMethodsWithBaseline(cal, pageURL, methods, body, nil)
}

// paramReplayChanged reports whether sending the parameter body produced a
// materially different response from the same endpoint+method sent with no body.
// It compares the coarse (status|words|lines) signature — the same signal the
// auto-calibrator trusts — so per-request jitter such as a rotating CSRF token
// does not read as a change, while a different status or a differently sized body
// (the sign the endpoint actually consumed the parameters) does.
func paramReplayChanged(paramStatus int, paramBody []byte, baseStatus int, baseBody []byte) bool {
	return pageSig(paramStatus, paramBody) != pageSig(baseStatus, baseBody)
}

// probeParamReplayMethods replays a discovered parameter body against pageURL and
// returns only the methods on which the parameters genuinely worked: a body-bearing
// verb (POST/PUT/PATCH) whose response is non-error, is not the level's learned
// catch-all for that verb, AND differs from that same verb's empty-body baseline
// against this same endpoint.
//
// The empty-body baseline is the check plain method probing lacks. Many hosts —
// SSR/Next.js shells especially — answer every path and verb with an identical
// soft-200, so probeURLMethods reports the parameters as "working" on directories
// that never consume them, including static-asset levels. Requiring the parameter
// response to differ from the endpoint's own no-body response attributes a
// parameter to an endpoint only when it actually changed what that endpoint
// returned. GET/DELETE/OPTIONS are excluded outright: they carry no body, so
// annotating them with a replayed body was always misleading.
//
// The baseline request is issued only after the parameter response already looks
// like a hit, so an endpoint that rejects the verb outright costs a single probe,
// not two.
func probeParamReplayMethods(cal *autoCalibrator, pageURL string, methods []string, body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	var worked []string
	for _, m := range methods {
		if !bodyMethods[m] {
			continue
		}
		presp, err := fetchURLResponseMethodSameScope(pageURL, m, body)
		if err != nil {
			continue
		}
		pdata, _ := io.ReadAll(io.LimitReader(presp.Body, 2<<20))
		presp.Body.Close()
		if !methodWorks(cal, m, pageURL, presp.StatusCode, pdata) {
			continue
		}
		bresp, err := fetchURLResponseMethodSameScope(pageURL, m, "")
		if err != nil {
			continue
		}
		bdata, _ := io.ReadAll(io.LimitReader(bresp.Body, 2<<20))
		bresp.Body.Close()
		if paramReplayChanged(presp.StatusCode, pdata, bresp.StatusCode, bdata) {
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
