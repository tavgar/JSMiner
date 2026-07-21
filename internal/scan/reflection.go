package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Reflection scanning is a lightweight, non-browser companion to the DOM
// scanner. Where -dom instruments the rendered page to find source-to-sink DOM
// XSS flows, reflection scanning replays the very same gathered parameters
// (static JS-mined, passive-archive and on-page query names) with a distinctive
// marker and inspects the raw HTTP response body for a *server-side* reflection.
// It never renders, never executes anything (the probe carries only inert HTML
// metacharacters, no script or event handler) and never leaves the target's
// scope, so it is safe to run alongside a normal scan.

// ReflectionSchemaVersion identifies the reflection-finding output schema. Bump
// the minor version when adding fields, the major version when changing an
// existing field's meaning.
const ReflectionSchemaVersion = "reflection.1.0"

// ReflectionType is the stable finding-type identifier for a reflected input,
// distinct from the DOM finding types so downstream triage can key off it.
const ReflectionType = "reflection"

// Reflection contexts classify where in the response body the marker landed.
// They are stable public strings emitted in findings.
const (
	ReflectionContextHTMLText    = "html_text"
	ReflectionContextHTMLAttr    = "html_attribute"
	ReflectionContextHTMLComment = "html_comment"
	ReflectionContextScript      = "script"
	ReflectionContextUnknown     = "unknown"
)

// reflectionCharset is the ordered set of inert HTML/JS breakout metacharacters
// embedded between the two markers so their survival (unencoded) reveals whether
// a reflection could break out of its context. None of these characters form an
// executing construct on their own, so the probe never runs code.
const reflectionCharset = "<>\"'`"

var reflectionBreakoutChars = []struct {
	ch    byte
	label string
}{
	{'<', "<"}, {'>', ">"}, {'"', "\""}, {'\'', "'"}, {'`', "`"},
}

// ReflectionScanConfig configures a reflection scan. Its bounds are independent
// of the DOM scan's so the two can be tuned separately, and it reuses the
// package's shared HTTP client, headers, TLS, redirect, throttle and timeout
// configuration.
type ReflectionScanConfig struct {
	// MaxURLs bounds how many distinct routes are probed (0 = unlimited).
	MaxURLs int
	// MaxParams bounds how many parameter names are tested per route.
	MaxParams int
	// MaxProbes bounds the total number of HTTP requests the whole scan may send
	// (0 = unlimited), so a large parameter corpus cannot cause unbounded traffic.
	MaxProbes int
	// Workers is the number of routes probed in parallel.
	Workers int

	// ParamHints are the parameter names mined for the DOM scan. Only url_query
	// hints are used; each route also tests its own existing query-string names.
	ParamHints []DOMSourceHint

	// AllowExternal permits a probe's redirects to leave the target's scope. Off
	// by default so a reflection probe can never become a redirect-driven SSRF.
	AllowExternal bool

	// Progress, when set, receives short human-readable status lines (stderr).
	Progress func(msg string)
}

// DefaultReflectionScanConfig returns conservative defaults mirroring the DOM
// scan's page/param/probe bounds and worker count.
func DefaultReflectionScanConfig() ReflectionScanConfig {
	return ReflectionScanConfig{
		MaxURLs:   50,
		MaxParams: 100,
		MaxProbes: 1000,
		Workers:   4,
	}
}

// ReflectionFinding is one parameter whose value was reflected into a target's
// HTTP response. It is intentionally a distinct model from DOMFinding: this is a
// server-side reflection observed without a browser, not a DOM source-to-sink
// flow.
type ReflectionFinding struct {
	Type      string `json:"type"`
	Target    string `json:"target"`   // scheme://host
	PageURL   string `json:"page_url"` // route probed (path + query name), marker redacted
	Parameter string `json:"parameter"`
	Method    string `json:"method"`

	// Context classifies where the marker landed: html_text, html_attribute,
	// html_comment, script or unknown.
	Context string `json:"context"`

	// Occurrences is how many times the marker was reflected in the response.
	Occurrences int `json:"occurrences,omitempty"`

	// Unfiltered lists the breakout metacharacters that were reflected without
	// encoding. An empty list on a reflected finding means the dangerous
	// characters were encoded (or their survival could not be determined).
	Unfiltered []string `json:"unfiltered,omitempty"`

	// ValuePreview is a bounded, redaction-safe excerpt of the response around the
	// reflection point.
	ValuePreview string `json:"value_preview,omitempty"`

	// DiscoveredBy records how the parameter name was learnt (JS access, request
	// body, passive archive, or the route's own query string).
	DiscoveredBy []string `json:"discovered_by,omitempty"`

	Severity   string     `json:"severity"`
	Confidence string     `json:"confidence"`
	Triage     *DOMTriage `json:"triage,omitempty"`

	// Fingerprint is a deterministic dedup identity derived only from stable
	// properties (never from the random marker).
	Fingerprint string `json:"fingerprint,omitempty"`

	// Notes carries advisory diagnostics (e.g. that the reflection boundary was
	// altered so character filtering could not be determined).
	Notes string `json:"notes,omitempty"`
}

// ReflectionScanSummary is the machine-readable end-of-scan record.
type ReflectionScanSummary struct {
	SchemaVersion      string         `json:"schema_version"`
	URLsScanned        int            `json:"urls_scanned"`
	URLsFailed         int            `json:"urls_failed"`
	ProbesSent         int            `json:"probes_sent"`
	ProbesLimit        int            `json:"probes_limit"`
	ParamsTested       int            `json:"params_tested"`
	Findings           int            `json:"findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Partial            bool           `json:"partial"`
	DurationMS         int64          `json:"duration_ms"`
	Errors             []string       `json:"errors,omitempty"`
}

// ReflectionScanResult is the deduplicated findings and the summary of a scan.
type ReflectionScanResult struct {
	Findings []ReflectionFinding
	Summary  ReflectionScanSummary
}

// reflectionScanner holds the mutable, synchronised state of a running scan.
type reflectionScanner struct {
	cfg ReflectionScanConfig

	mu           sync.Mutex
	findings     []ReflectionFinding
	probes       int
	urlsScanned  int
	urlsFailed   int
	paramsTested int
	errs         []string
	partial      bool
}

// reflectionProbe is one parameter's marker pair injected into a request.
type reflectionProbe struct {
	param        string
	discoveredBy []string
	pre          string // leading alphanumeric marker
	suf          string // trailing alphanumeric marker
	value        string // pre + reflectionCharset + suf
}

// maxReflectionInjectedURLLength bounds a single probe URL so a huge parameter
// corpus cannot build a pathological request line.
const maxReflectionInjectedURLLength = 16 << 10

// reflectionBatchMax caps how many parameters ride one request, keeping URLs
// reasonable and limiting cross-parameter interference.
const reflectionBatchMax = 25

// ScanReflections replays gathered parameters against the given URL targets and
// reports server-side reflections. It reuses the package's HTTP client, headers,
// TLS, redirect, throttle and timeout configuration, stays within each target's
// scope (unless AllowExternal), and honours the URL, parameter and probe budgets.
// Context cancellation stops the scan cleanly and marks the result partial.
func (e *Extractor) ScanReflections(ctx context.Context, targets []string, cfg ReflectionScanConfig) (ReflectionScanResult, error) {
	start := time.Now()
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.MaxParams <= 0 {
		cfg.MaxParams = DefaultReflectionScanConfig().MaxParams
	}
	s := &reflectionScanner{cfg: cfg}

	routes := reflectionRoutes(targets, cfg.MaxURLs)
	hintIndex := reflectionParamHints(cfg.ParamHints)

	sem := make(chan struct{}, cfg.Workers)
	var wg sync.WaitGroup
	for _, route := range routes {
		if ctx.Err() != nil {
			break
		}
		if s.budgetExhausted() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(route string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.scanRoute(ctx, route, hintIndex)
		}(route)
	}
	wg.Wait()

	result := ReflectionScanResult{Findings: DedupReflectionFindings(s.snapshotFindings())}
	result.Summary = s.buildSummary(cfg, result.Findings, time.Since(start))
	if ctx.Err() != nil {
		result.Summary.Partial = true
	}
	return result, nil
}

// scanRoute tests every candidate parameter of one route for reflection,
// batching the parameters into as few requests as the URL-length and batch
// bounds allow.
func (s *reflectionScanner) scanRoute(ctx context.Context, route string, hintIndex map[string][]DOMSourceHint) {
	u, err := url.Parse(route)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		s.addErr(fmt.Sprintf("skip non-URL target %q", route))
		return
	}
	probes := s.buildProbes(u, hintIndex)
	if len(probes) == 0 {
		return
	}
	s.addParamsTested(len(probes))
	if s.cfg.Progress != nil {
		s.cfg.Progress(fmt.Sprintf("[reflection] %s (%d param(s))", route, len(probes)))
	}

	for _, batch := range s.batchProbes(u, probes) {
		if ctx.Err() != nil {
			return
		}
		if !s.reserveProbe() {
			return
		}
		reqURL, ok := reflectionRequestURL(u, batch)
		if !ok {
			continue
		}
		body, err := s.fetchBody(reqURL, u.Hostname())
		if err != nil {
			s.urlFailed(fmt.Sprintf("route %s: %v", route, err))
			continue
		}
		s.urlDone()
		lowered := bytes.ToLower(body)
		for _, p := range batch {
			if f, ok := analyzeReflection(u, p, body, lowered); ok {
				s.addFinding(f)
			}
		}
	}
}

// buildProbes assembles the ordered candidate parameter set for a route: its own
// query-string names first (deterministic), then same-scope url_query hints,
// bounded by MaxParams.
func (s *reflectionScanner) buildProbes(u *url.URL, hintIndex map[string][]DOMSourceHint) []reflectionProbe {
	seen := make(map[string]bool)
	var probes []reflectionProbe
	add := func(name string, discovered []string) {
		if len(probes) >= s.cfg.MaxParams {
			return
		}
		if !validDOMSourceHintName(name) || seen[name] {
			return
		}
		seen[name] = true
		pre := "jsmrp" + randomToken()
		suf := "jsmrs" + randomToken()
		probes = append(probes, reflectionProbe{
			param:        name,
			discoveredBy: uniqueSortedStrings(discovered),
			pre:          pre,
			suf:          suf,
			value:        pre + reflectionCharset + suf,
		})
	}

	names := make([]string, 0, len(u.Query()))
	for name := range u.Query() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(name, []string{"page_url"})
	}

	for _, hint := range hintIndex[canonicalHost(u.Hostname())] {
		add(hint.Name, hint.Discovered)
	}
	return probes
}

// batchProbes splits a route's probes into request-sized batches, each bounded
// by reflectionBatchMax parameters and the injected-URL length cap.
func (s *reflectionScanner) batchProbes(u *url.URL, probes []reflectionProbe) [][]reflectionProbe {
	var batches [][]reflectionProbe
	var cur []reflectionProbe
	flush := func() {
		if len(cur) > 0 {
			batches = append(batches, cur)
			cur = nil
		}
	}
	for _, p := range probes {
		trial := append(append([]reflectionProbe(nil), cur...), p)
		if reqURL, ok := reflectionRequestURL(u, trial); !ok || len(reqURL) > maxReflectionInjectedURLLength {
			flush()
			// A single parameter that alone overflows the cap is dropped rather than
			// sent malformed.
			if reqURL, ok := reflectionRequestURL(u, []reflectionProbe{p}); ok && len(reqURL) <= maxReflectionInjectedURLLength {
				cur = []reflectionProbe{p}
			}
			continue
		}
		cur = append(cur, p)
		if len(cur) >= reflectionBatchMax {
			flush()
		}
	}
	flush()
	return batches
}

// reflectionRequestURL renders the route with every probe in the batch injected
// into the query string, overwriting any existing value for that name.
func reflectionRequestURL(u *url.URL, batch []reflectionProbe) (string, bool) {
	if len(batch) == 0 {
		return "", false
	}
	q := u.Query()
	for _, p := range batch {
		q.Set(p.param, p.value)
	}
	c := *u
	c.RawQuery = q.Encode()
	return c.String(), true
}

// fetchBody retrieves a probe URL and returns its capped response body, keeping
// redirects within the target's scope unless external probing is allowed.
func (s *reflectionScanner) fetchBody(reqURL, baseHost string) ([]byte, error) {
	var (
		resp *http.Response
		err  error
	)
	if s.cfg.AllowExternal {
		resp, err = fetchURLResponse(reqURL)
	} else {
		resp, err = fetchURLResponseScoped(reqURL, baseHost)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if isBinaryContentType(resp.Header.Get("Content-Type")) {
		return nil, nil
	}
	return readCappedBody(resp.Body)
}

// analyzeReflection looks for probe p's marker in the response. When found it
// classifies the context, determines which breakout characters survived
// unencoded, and builds a finding. body is the raw response; lowered is its
// lowercase form, shared across the batch for the structural context search.
func analyzeReflection(u *url.URL, p reflectionProbe, body, lowered []byte) (ReflectionFinding, bool) {
	first := bytes.Index(body, []byte(p.pre))
	if first < 0 {
		return ReflectionFinding{}, false
	}
	occurrences := bytes.Count(body, []byte(p.pre))
	context := classifyReflectionContext(lowered, first)

	unfiltered, notes := reflectionUnfiltered(body, p, first)
	severity, confidence, triage := classifyReflection(context, unfiltered)

	f := ReflectionFinding{
		Type:         ReflectionType,
		Target:       (&url.URL{Scheme: u.Scheme, Host: u.Host}).String(),
		PageURL:      reflectionRouteLabel(u, p.param),
		Parameter:    p.param,
		Method:       "GET",
		Context:      context,
		Occurrences:  occurrences,
		Unfiltered:   unfiltered,
		ValuePreview: reflectionPreview(body, first),
		DiscoveredBy: p.discoveredBy,
		Severity:     severity,
		Confidence:   confidence,
		Triage:       triage,
		Notes:        notes,
	}
	f.Fingerprint = f.computeFingerprint()
	return f, true
}

// reflectionUnfiltered returns the breakout metacharacters reflected without
// encoding, by isolating the segment the probe placed between its two markers.
// If the trailing marker is missing (the reflection was truncated or reshaped),
// character survival cannot be determined and a note explains why.
func reflectionUnfiltered(body []byte, p reflectionProbe, first int) ([]string, string) {
	afterPre := first + len(p.pre)
	if afterPre > len(body) {
		return nil, ""
	}
	window := body[afterPre:]
	// The metacharacters sit immediately after the leading marker; bound the search
	// so an unrelated later occurrence of the trailing marker is not mistaken for
	// this reflection's boundary.
	const lookahead = 256
	if len(window) > lookahead {
		window = window[:lookahead]
	}
	sufIdx := bytes.Index(window, []byte(p.suf))
	if sufIdx < 0 {
		return nil, "reflection boundary altered; character filtering not determined"
	}
	middle := window[:sufIdx]
	var out []string
	for _, bc := range reflectionBreakoutChars {
		if bytes.IndexByte(middle, bc.ch) >= 0 {
			out = append(out, bc.label)
		}
	}
	return out, ""
}

// classifyReflectionContext determines where in the document the marker at idx
// landed. lowered is the lowercased body so tag/script/comment matching is
// case-insensitive; idx indexes into it. Script and comment contexts take
// precedence over attribute detection.
func classifyReflectionContext(lowered []byte, idx int) string {
	if idx < 0 || idx > len(lowered) {
		return ReflectionContextUnknown
	}
	prefix := lowered[:idx]

	if lastIndexBefore(prefix, "<!--") > lastIndexBefore(prefix, "-->") {
		return ReflectionContextHTMLComment
	}
	openScript := lastScriptOpen(prefix)
	if openScript > lastIndexBefore(prefix, "</script") {
		return ReflectionContextScript
	}

	lt := bytes.LastIndexByte(prefix, '<')
	gt := bytes.LastIndexByte(prefix, '>')
	if lt > gt {
		return ReflectionContextHTMLAttr
	}
	return ReflectionContextHTMLText
}

// lastScriptOpen returns the index of the last opening <script tag (i.e. "<script"
// followed by a space, '>' or tab) before the end of prefix, or -1.
func lastScriptOpen(prefix []byte) int {
	best := -1
	for i := 0; ; {
		j := bytes.Index(prefix[i:], []byte("<script"))
		if j < 0 {
			break
		}
		pos := i + j
		after := pos + len("<script")
		if after >= len(prefix) || prefix[after] == ' ' || prefix[after] == '>' || prefix[after] == '\t' || prefix[after] == '\n' || prefix[after] == '\r' {
			best = pos
		}
		i = pos + len("<script")
	}
	return best
}

func lastIndexBefore(prefix []byte, needle string) int {
	return bytes.LastIndex(prefix, []byte(needle))
}

// classifyReflection maps a reflection context and the surviving breakout
// characters to a severity/confidence pair and a plain-language triage hint.
// Severity is deliberately capped at medium: a reflection is a strong candidate
// but execution is never confirmed without a browser, so the scanner does not
// claim exploitability.
func classifyReflection(context string, unfiltered []string) (severity, confidence string, triage *DOMTriage) {
	has := func(labels ...string) bool {
		for _, want := range labels {
			for _, got := range unfiltered {
				if got == want {
					return true
				}
			}
		}
		return false
	}
	switch context {
	case ReflectionContextScript:
		if has("\"", "'", "`") {
			return SeverityMedium, ConfidenceHigh, &DOMTriage{Verdict: DOMTriageWorthReview,
				Reason: "reflected into a <script> context with string-breakout characters unencoded"}
		}
		return SeverityLow, ConfidenceMedium, &DOMTriage{Verdict: DOMTriageWorthReview,
			Reason: "reflected into a <script> context; string-breakout characters were encoded"}
	case ReflectionContextHTMLText:
		if has("<") && has(">") {
			return SeverityMedium, ConfidenceHigh, &DOMTriage{Verdict: DOMTriageWorthReview,
				Reason: "reflected into HTML text with angle brackets unencoded"}
		}
		return SeverityLow, ConfidenceMedium, &DOMTriage{Verdict: DOMTriageLikelyBenign,
			Reason: "reflected in HTML text but angle brackets were encoded"}
	case ReflectionContextHTMLAttr:
		if has("\"", "'") {
			return SeverityMedium, ConfidenceHigh, &DOMTriage{Verdict: DOMTriageWorthReview,
				Reason: "reflected into an HTML attribute with quote characters unencoded"}
		}
		return SeverityLow, ConfidenceMedium, &DOMTriage{Verdict: DOMTriageLikelyBenign,
			Reason: "reflected in an HTML attribute but quote characters were encoded"}
	case ReflectionContextHTMLComment:
		if has("<") && has(">") {
			return SeverityLow, ConfidenceMedium, &DOMTriage{Verdict: DOMTriageWorthReview,
				Reason: "reflected inside an HTML comment with comment-breakout characters unencoded"}
		}
		return SeverityInfo, ConfidenceMedium, &DOMTriage{Verdict: DOMTriageLikelyBenign,
			Reason: "reflected inside an HTML comment; breakout characters were encoded"}
	default:
		return SeverityLow, ConfidenceLow, &DOMTriage{Verdict: DOMTriageWorthReview,
			Reason: "input was reflected in the response; context could not be classified"}
	}
}

// ---- identity, dedup & ordering --------------------------------------------

// computeFingerprint derives a deterministic identity from stable properties
// only: type, target origin, route, parameter and context. The random marker,
// occurrence count and surviving-character set never enter it.
func (f *ReflectionFinding) computeFingerprint() string {
	var b strings.Builder
	for _, p := range []string{f.Type, originOf(f.Target), routeOf(f.PageURL), f.Parameter, f.Context} {
		b.WriteString(p)
		b.WriteByte('\x1f')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum[:16])
}

// DedupReflectionFindings collapses findings that share a fingerprint into one
// record, keeping the strongest severity/confidence and the union of surviving
// characters and discovery sources. The result is deterministically ordered
// (severity desc, then fingerprint asc).
func DedupReflectionFindings(findings []ReflectionFinding) []ReflectionFinding {
	type entry struct {
		f     ReflectionFinding
		order int
	}
	byFP := make(map[string]*entry)
	var order int
	for i := range findings {
		f := findings[i]
		f.Fingerprint = f.computeFingerprint()
		e, ok := byFP[f.Fingerprint]
		if !ok {
			byFP[f.Fingerprint] = &entry{f: f, order: order}
			order++
			continue
		}
		if severityRank(f.Severity) > severityRank(e.f.Severity) {
			e.f.Severity = f.Severity
		}
		if confidenceRank(f.Confidence) > confidenceRank(e.f.Confidence) {
			e.f.Confidence = f.Confidence
		}
		if f.Occurrences > e.f.Occurrences {
			e.f.Occurrences = f.Occurrences
		}
		e.f.Unfiltered = uniqueSortedStrings(append(e.f.Unfiltered, f.Unfiltered...))
		e.f.DiscoveredBy = uniqueSortedStrings(append(e.f.DiscoveredBy, f.DiscoveredBy...))
		if e.f.ValuePreview == "" {
			e.f.ValuePreview = f.ValuePreview
		}
		if e.f.Notes == "" {
			e.f.Notes = f.Notes
		}
	}

	out := make([]ReflectionFinding, 0, len(byFP))
	for _, e := range byFP {
		e.f.Triage = reflectionTriageFor(e.f)
		out = append(out, e.f)
	}
	SortReflectionFindings(out)
	return out
}

// reflectionTriageFor re-derives the triage hint after any dedup merging so the
// verdict always describes the final record.
func reflectionTriageFor(f ReflectionFinding) *DOMTriage {
	_, _, triage := classifyReflection(f.Context, f.Unfiltered)
	return triage
}

// SortReflectionFindings orders findings by severity (desc) then fingerprint
// (asc) for stable, reproducible output.
func SortReflectionFindings(findings []ReflectionFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}

// ---- helpers ---------------------------------------------------------------

// reflectionRoutes normalises and de-duplicates the seed URLs into distinct
// routes (scheme, host, path and the set of query-parameter names), bounded by
// max, so value-only variants of one route collapse to a single probe target.
func reflectionRoutes(targets []string, max int) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, t := range targets {
		u, err := url.Parse(strings.TrimSpace(t))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		u.Fragment = ""
		names := make([]string, 0, len(u.Query()))
		for name := range u.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		key := u.Scheme + "://" + u.Host + u.Path + "?" + strings.Join(names, "&")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u.String())
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

// reflectionParamHints indexes the url_query hints by canonical host so each
// route only tests names discovered in its own scope.
func reflectionParamHints(hints []DOMSourceHint) map[string][]DOMSourceHint {
	byHost := make(map[string]map[string]DOMSourceHint)
	for _, hint := range hints {
		if hint.Kind != SourceURLQuery || !validDOMSourceHintName(hint.Name) {
			continue
		}
		host := canonicalHost(hint.ScopeHost)
		if byHost[host] == nil {
			byHost[host] = make(map[string]DOMSourceHint)
		}
		if old, ok := byHost[host][hint.Name]; ok {
			old.Discovered = uniqueSortedStrings(append(old.Discovered, hint.Discovered...))
			byHost[host][hint.Name] = old
		} else {
			hint.Discovered = uniqueSortedStrings(hint.Discovered)
			byHost[host][hint.Name] = hint
		}
	}
	out := make(map[string][]DOMSourceHint, len(byHost))
	for host, m := range byHost {
		list := make([]DOMSourceHint, 0, len(m))
		for _, h := range m {
			list = append(list, h)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		out[host] = list
	}
	return out
}

func canonicalHost(host string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "www.")
}

// reflectionRouteLabel renders a route with the tested parameter shown but its
// value redacted, so output identifies the reflection without echoing the marker.
func reflectionRouteLabel(u *url.URL, param string) string {
	c := *u
	q := c.Query()
	q.Set(param, "")
	c.RawQuery = q.Encode()
	label := c.String()
	// url.Values.Encode() renders an empty value as "param=" — keep it, it reads
	// clearly as "this parameter, value elided".
	return label
}

// reflectionPreview returns a bounded, redaction-safe excerpt of the response
// around the reflection point, with the surrounding markup for context.
func reflectionPreview(body []byte, idx int) string {
	const pad = 40
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + pad
	if end > len(body) {
		end = len(body)
	}
	excerpt := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, string(body[start:end]))
	return boundPreview(strings.TrimSpace(excerpt))
}

// ---- counters & bookkeeping ------------------------------------------------

func (s *reflectionScanner) reserveProbe() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxProbes > 0 && s.probes+1 > s.cfg.MaxProbes {
		s.partial = true
		return false
	}
	s.probes++
	return true
}

func (s *reflectionScanner) budgetExhausted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.MaxProbes > 0 && s.probes >= s.cfg.MaxProbes
}

func (s *reflectionScanner) addFinding(f ReflectionFinding) {
	s.mu.Lock()
	s.findings = append(s.findings, f)
	s.mu.Unlock()
}

func (s *reflectionScanner) addParamsTested(n int) {
	s.mu.Lock()
	s.paramsTested += n
	s.mu.Unlock()
}

func (s *reflectionScanner) urlDone() {
	s.mu.Lock()
	s.urlsScanned++
	s.mu.Unlock()
}

func (s *reflectionScanner) urlFailed(msg string) {
	s.mu.Lock()
	s.urlsFailed++
	s.errs = append(s.errs, msg)
	s.mu.Unlock()
}

func (s *reflectionScanner) addErr(msg string) {
	s.mu.Lock()
	s.errs = append(s.errs, msg)
	s.mu.Unlock()
}

func (s *reflectionScanner) snapshotFindings() []ReflectionFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReflectionFinding, len(s.findings))
	copy(out, s.findings)
	return out
}

func (s *reflectionScanner) buildSummary(cfg ReflectionScanConfig, findings []ReflectionFinding, dur time.Duration) ReflectionScanSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySev := map[string]int{SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, f := range findings {
		bySev[strings.ToLower(f.Severity)]++
	}
	return ReflectionScanSummary{
		SchemaVersion:      ReflectionSchemaVersion,
		URLsScanned:        s.urlsScanned,
		URLsFailed:         s.urlsFailed,
		ProbesSent:         s.probes,
		ProbesLimit:        cfg.MaxProbes,
		ParamsTested:       s.paramsTested,
		Findings:           len(findings),
		FindingsBySeverity: bySev,
		Partial:            s.partial || s.urlsFailed > 0,
		DurationMS:         dur.Milliseconds(),
		Errors:             append([]string(nil), s.errs...),
	}
}
