package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// DOM scanning modes.
const (
	DOMModeObserve = "observe"
	DOMModeCanary  = "canary"
	DOMModeConfirm = "confirm"
)

// Source-family identifiers. These are the source.kind values in findings and
// the tokens accepted by -dom-sources, so they are stable public strings.
const (
	SourceURLQuery       = "url_query"
	SourceURLFragment    = "url_fragment"
	SourceURLFull        = "url_full"
	SourceLocation       = "location"
	SourceReferrer       = "referrer"
	SourceWindowName     = "window_name"
	SourceFormInput      = "form_input"
	SourceCookie         = "cookie"
	SourceLocalStorage   = "local_storage"
	SourceSessionStorage = "session_storage"
	SourceWebMessage     = "web_message"
)

// allSourceFamilies lists every source the scanner directly seeds. url_full and
// location are not seeded directly (they are read from the URL, which the query
// and fragment canaries already cover), so they are offered only as aliases.
var allSourceFamilies = []string{
	SourceURLQuery, SourceURLFragment, SourceReferrer,
	SourceWindowName, SourceFormInput, SourceCookie, SourceLocalStorage,
	SourceSessionStorage, SourceWebMessage,
}

// allSinkFamilies lists every sink family the agent can hook, used for
// -dom-sinks validation and the default (all enabled).
var allSinkFamilies = []string{
	"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "srcdoc",
	"eval", "Function", "setTimeout", "script.src", "navigation", "event-handler",
}

// DOMSourceFamilies returns the directly-selectable source families for
// -dom-sources validation.
func DOMSourceFamilies() []string { return append([]string(nil), allSourceFamilies...) }

// DOMSinkFamilies returns the selectable sink families for -dom-sinks validation.
func DOMSinkFamilies() []string { return append([]string(nil), allSinkFamilies...) }

// DOMSourceAliases maps convenience source names to the concrete families that
// implement them. url_full and location both read from the URL, which the query
// and fragment canaries cover.
func DOMSourceAliases() map[string][]string {
	return map[string][]string{
		SourceURLFull:  {SourceURLQuery, SourceURLFragment},
		SourceLocation: {SourceURLQuery, SourceURLFragment},
	}
}

// DOMScanConfig configures a DOM vulnerability scan. Every limit is independent
// of the crawl's own limits so DOM scanning can be bounded on its own terms.
type DOMScanConfig struct {
	Mode        string
	MaxPages    int
	MaxProbes   int
	Workers     int
	PageTimeout time.Duration

	// Sources and Sinks, when non-nil, restrict the enabled source families and
	// sink families respectively. Nil means all enabled.
	Sources map[string]bool
	Sinks   map[string]bool

	// Messages enables postMessage analysis as a separately controllable feature.
	Messages bool

	// Crawl follows in-scope links discovered in the rendered DOM to reach more
	// pages, bounded by MaxPages and MaxDepth. Off scans only the seed targets.
	Crawl    bool
	MaxDepth int

	// AllowExternal permits navigation to and probing of third-party origins. Off
	// by default: generated probes must not be sent off-scope, and a client-side
	// redirect out of scope is not followed for probing.
	AllowExternal bool

	// Progress, when set, receives short human-readable status lines (stderr).
	Progress func(msg string)
}

// DefaultDOMScanConfig returns the default DOM scan configuration: canary mode,
// bounded pages and probes, a modest worker pool and postMessage analysis on.
func DefaultDOMScanConfig() DOMScanConfig {
	return DOMScanConfig{
		Mode:        DOMModeCanary,
		MaxPages:    50,
		MaxProbes:   1000,
		Workers:     4,
		PageTimeout: 25 * time.Second,
		Messages:    true,
		MaxDepth:    2,
	}
}

// DOMScanSummary is the machine-readable end-of-scan record.
type DOMScanSummary struct {
	SchemaVersion      string         `json:"schema_version"`
	Mode               string         `json:"mode"`
	PagesScanned       int            `json:"pages_scanned"`
	PagesFailed        int            `json:"pages_failed"`
	ProbesSent         int            `json:"probes_sent"`
	ProbesLimit        int            `json:"probes_limit"`
	MaxPages           int            `json:"max_pages"`
	Findings           int            `json:"findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Partial            bool           `json:"partial"`
	TimedOut           bool           `json:"timed_out"`
	DurationMS         int64          `json:"duration_ms"`
	Errors             []string       `json:"errors,omitempty"`
}

// DOMScanResult is the deduplicated findings and the summary of a DOM scan.
type DOMScanResult struct {
	Findings []DOMFinding
	Summary  DOMScanSummary
}

// domScanner holds the mutable state of a running DOM scan, shared (and
// synchronised) across its worker goroutines.
type domScanner struct {
	cfg DOMScanConfig

	mu           sync.Mutex
	findings     []DOMFinding
	probes       int
	pagesScanned int
	pagesFailed  int
	errs         []string
	partial      bool
	timedOut     bool
	visited      map[string]struct{}
}

// ScanDOM runs the opt-in DOM vulnerability scan over the given URL targets. It
// reuses the package's browser provisioning, headers/cookies, TLS, redirect,
// throttle and timeout configuration. It never changes any behaviour unless
// called, and returns findings plus a summary. A single failed page does not
// discard findings from successful pages; context cancellation stops active
// browser work cleanly and yields a clearly-marked partial result.
func (e *Extractor) ScanDOM(ctx context.Context, targets []string, cfg DOMScanConfig) (DOMScanResult, error) {
	start := time.Now()
	if cfg.Mode == "" {
		cfg.Mode = DOMModeCanary
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.PageTimeout <= 0 {
		cfg.PageTimeout = 25 * time.Second
	}
	s := &domScanner{cfg: cfg, visited: make(map[string]struct{})}

	for _, target := range targets {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			s.addErr(fmt.Sprintf("skip non-URL target %q", target))
			continue
		}
		if ctx.Err() != nil {
			break
		}
		s.scanSeed(ctx, u)
	}

	result := DOMScanResult{Findings: DedupDOMFindings(s.snapshotFindings())}
	result.Summary = s.buildSummary(cfg, len(result.Findings), result.Findings, time.Since(start))
	if ctx.Err() != nil {
		result.Summary.Partial = true
		if ctx.Err() == context.DeadlineExceeded {
			result.Summary.TimedOut = true
		}
	}
	return result, nil
}

// scanSeed runs a bounded, level-by-level breadth-first DOM scan rooted at one
// seed URL. It stays within the seed's scope (unless AllowExternal) and honours
// the page and probe budgets.
func (s *domScanner) scanSeed(ctx context.Context, seed *url.URL) {
	baseHost := seed.Hostname()
	frontier := []string{seed.String()}
	depth := 0
	maxDepth := s.cfg.MaxDepth
	if !s.cfg.Crawl {
		maxDepth = 0
	}

	for len(frontier) > 0 {
		if ctx.Err() != nil {
			return
		}
		if maxDepth >= 0 && depth > maxDepth {
			return
		}
		next := s.processFrontier(ctx, baseHost, frontier)
		if s.budgetExhausted() {
			return
		}
		frontier = next
		depth++
	}
}

// processFrontier scans every page in the frontier concurrently (bounded by the
// worker pool) and returns the next frontier of in-scope, unvisited links.
func (s *domScanner) processFrontier(ctx context.Context, baseHost string, frontier []string) []string {
	sem := make(chan struct{}, s.cfg.Workers)
	var wg sync.WaitGroup
	var linkMu sync.Mutex
	nextSet := make(map[string]struct{})
	var next []string

	for _, pageURL := range frontier {
		if ctx.Err() != nil {
			break
		}
		if !s.reservePage(pageURL) {
			continue // already visited or page budget reached
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pageURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			links, err := s.scanPage(ctx, baseHost, pageURL)
			if err != nil {
				s.pageFailed(fmt.Sprintf("page %s: %v", pageURL, err))
				return
			}
			s.pageDone()
			if !s.cfg.Crawl {
				return
			}
			linkMu.Lock()
			for _, l := range links {
				if _, ok := nextSet[l]; ok {
					continue
				}
				nextSet[l] = struct{}{}
				next = append(next, l)
			}
			linkMu.Unlock()
		}(pageURL)
	}
	wg.Wait()
	sort.Strings(next) // deterministic frontier ordering
	return next
}

// scanPage runs every applicable probe pass against one page in a single fresh
// browser context, then returns the in-scope links discovered for the crawl.
func (s *domScanner) scanPage(ctx context.Context, baseHost, pageURL string) ([]string, error) {
	if s.cfg.Progress != nil {
		s.cfg.Progress(fmt.Sprintf("[dom] scanning %s (%s)", pageURL, s.cfg.Mode))
	}

	// Pace against the shared throttle before arming the per-page timeout, so a
	// backoff sleep cannot consume the page budget.
	globalThrottle.waitHost(hostOf(pageURL))

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, renderExecOptions()...)
	defer cancelAlloc()
	pctx, cancelCtx := newRenderContext(allocCtx)
	defer cancelCtx()
	pctx, cancelTimeout := context.WithTimeout(pctx, s.cfg.PageTimeout)
	defer cancelTimeout()

	// Note render-time rate-limit responses so a 429 the browser hits backs off
	// the rest of the scan, exactly as the normal render path does.
	chromedp.ListenTarget(pctx, func(ev interface{}) {
		if e, ok := ev.(*network.EventResponseReceived); ok {
			noteRenderResponse(e.Response.URL, int(e.Response.Status), e.Response.Headers)
		}
	})

	relay := randomToken()

	switch s.cfg.Mode {
	case DOMModeObserve:
		return s.runObserve(pctx, baseHost, pageURL, relay)
	default: // canary and confirm both start from a canary pass
		return s.runCanary(pctx, baseHost, pageURL, relay)
	}
}

// runObserve loads the page with no input modification and records dangerous
// sink activity only. It still explores state via clicks (which do not change
// application inputs) so sinks reached after interaction are observed too.
func (s *domScanner) runObserve(ctx context.Context, baseHost, pageURL, relay string) ([]string, error) {
	agentSrc := buildDOMAgent(s.agentConfig(DOMModeObserve, relay, nil))
	if err := s.loadPage(ctx, agentSrc, pageURL, ""); err != nil {
		return nil, err
	}
	offset, st := s.readAndIngest(ctx, baseHost, pageURL, PhaseInitialLoad, TriggerPageLoad, "", 0)

	// Reveal further states through clicks; observe sinks there too.
	s.clickExplore(ctx)
	_, st = s.readAndIngest(ctx, baseHost, pageURL, PhaseStateExploration, TriggerInteraction, "click", offset)

	if brokeExecution(st) {
		s.note(pageURL, "instrumentation hook errors observed during load")
	}
	return s.collectLinks(ctx, baseHost)
}

// runCanary injects canary markers into every enabled source, records the
// source-to-sink flows they produce across the initial load, interaction and
// postMessage passes, and — in confirm mode — follows up with controlled,
// non-visible confirmation probes.
func (s *domScanner) runCanary(ctx context.Context, baseHost, pageURL, relay string) ([]string, error) {
	canaries, injectedURL, referrer := s.buildCanaries(pageURL)
	if !s.reserveProbes(len(canaries)) {
		// Probe budget exhausted before this page: fall back to a pure observation
		// so the page is still not wasted, but inject nothing.
		return s.runObserve(ctx, baseHost, pageURL, relay)
	}

	agentSrc := buildDOMAgent(s.agentConfig(s.cfg.Mode, relay, canaries))
	if err := s.loadPage(ctx, agentSrc, injectedURL, referrer); err != nil {
		return nil, err
	}

	// Scope guard: if a client-side redirect took the page off-scope, do not keep
	// probing or enqueue its links.
	if !s.inScopeNow(ctx, baseHost) {
		s.readAndIngest(ctx, baseHost, pageURL, PhaseInitialLoad, TriggerPageLoad, "", 0)
		s.note(pageURL, "page left scope via client-side navigation; probing stopped")
		return nil, nil
	}

	offset, _ := s.readAndIngest(ctx, baseHost, pageURL, PhaseInitialLoad, TriggerPageLoad, "", 0)

	// Interaction pass: fill forms with a form-input canary and submit, and click
	// controls, to reach event-triggered and delayed flows.
	if s.sourceEnabled(SourceFormInput) {
		if fic := s.formInputCanary(); s.reserveProbes(1) {
			canaries = append(canaries, fic)
			// The form-input canary must also be known to the agent; re-arming via a
			// fresh navigation would lose state, so push it to the agent's canary list
			// in-page before filling.
			s.addCanaryToAgent(ctx, fic)
			s.fillForms(ctx, fic.Value)
		}
	}
	// Always re-read after the interaction pass: filling forms and clicking can
	// drive event-triggered and delayed flows even when no control reported a click.
	s.clickExplore(ctx)
	offset, _ = s.readAndIngest(ctx, baseHost, pageURL, PhaseStateExploration, TriggerInteraction, "form/click", offset)

	// postMessage pass: deliver a canary via postMessage and record any flow.
	if s.cfg.Messages && s.sourceEnabled(SourceWebMessage) && s.reserveProbes(1) {
		wm := s.webMessageCanary()
		s.addCanaryToAgent(ctx, wm)
		s.sendWebMessage(ctx, wm.Value)
		offset, _ = s.readAndIngest(ctx, baseHost, pageURL, PhaseStateExploration, TriggerPostMessage, "postMessage", offset)
	}
	_ = offset

	// Confirm pass: for flows found so far, drive a controlled, hidden execution
	// probe. Bounded to the seed page's own flows.
	if s.cfg.Mode == DOMModeConfirm {
		s.runConfirm(ctx, baseHost, pageURL, relay)
	}

	stFinal, _ := readAgentState(ctx)
	if brokeExecution(stFinal) {
		s.note(pageURL, "instrumentation hook errors observed; page execution may be affected")
	}
	return s.collectLinks(ctx, baseHost)
}

// runConfirm re-probes each distinct source that produced an executable-context
// flow with a payload that calls a hidden confirmation beacon (never a visible
// dialog). A fired beacon upgrades the matching flows to confirmed execution.
func (s *domScanner) runConfirm(ctx context.Context, baseHost, pageURL, relay string) {
	type key struct{ kind, name, ctx string }
	targets := map[key]string{} // key -> probe id
	s.mu.Lock()
	for _, f := range s.findings {
		if f.Type != DOMTypeFlow || f.Source == nil {
			continue
		}
		if f.Context != "html" && f.Context != "js" {
			continue // only these contexts have a safe, controlled confirmation
		}
		targets[key{f.Source.Kind, f.Source.Name, f.Context}] = f.ProbeID
	}
	s.mu.Unlock()

	for k, pid := range targets {
		if ctx.Err() != nil || !s.reserveProbes(1) {
			return
		}
		payload := confirmPayload(k.ctx, pid)
		c := domCanary{ID: pid, Token: confirmMarker(pid), Kind: k.kind, Name: k.name, Value: payload}
		injected := s.injectSourceURL(pageURL, c)
		agentSrc := buildDOMAgent(s.agentConfig(DOMModeConfirm, relay, []domCanary{c}))
		if err := s.loadPage(ctx, agentSrc, injected, ""); err != nil {
			continue
		}
		if k.kind == SourceFormInput {
			s.fillForms(ctx, payload)
		} else if k.kind == SourceWebMessage {
			s.sendWebMessage(ctx, payload)
		}
		s.clickExplore(ctx)
		st, _ := readAgentState(ctx)
		if st.Confirmations[pid] {
			s.confirmFlows(pid)
		}
	}
}

// ---- browser action helpers ------------------------------------------------

// loadPage installs the agent (so it runs before page scripts, in every frame),
// navigates to urlStr with an optional referrer, and waits for the page to
// settle. Errors here are the page's own load failures, kept per-page.
func (s *domScanner) loadPage(ctx context.Context, agentSrc, urlStr, referrer string) error {
	actions := []chromedp.Action{network.Enable().WithMaxPostDataSize(MaxPostDataSize)}
	actions = append(actions, headerActions(renderHeaders())...)
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(agentSrc).Do(ctx)
		return err
	}))
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		p := page.Navigate(urlStr)
		if referrer != "" {
			p = p.WithReferrer(referrer)
		}
		_, _, errText, err := p.Do(ctx)
		if err != nil {
			return err
		}
		if errText != "" {
			return fmt.Errorf("navigate: %s", errText)
		}
		return nil
	}))
	actions = append(actions,
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(domSettle()),
	)
	return chromedp.Run(ctx, actions...)
}

// readAgentState reads the in-page agent state back as JSON and decodes it.
func readAgentState(ctx context.Context) (domAgentState, error) {
	var raw string
	expr := `JSON.stringify((function(){var a=window.__jsmdom;if(!a)return{findings:[],confirmations:{},hookErrors:0};return{findings:a.findings||[],confirmations:a.confirmations||{},hookErrors:a.hookErrors||0};})())`
	if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &raw)); err != nil {
		return domAgentState{}, err
	}
	var st domAgentState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return domAgentState{}, err
	}
	return st, nil
}

// addCanaryToAgent registers a canary with the already-loaded agent so a
// source seeded after the initial navigation (a form input, a web message) is
// still correlated, without a state-losing reload.
func (s *domScanner) addCanaryToAgent(ctx context.Context, c domCanary) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	expr := `(function(){try{if(window.__jsmdomAddCanary)window.__jsmdomAddCanary(` + string(data) + `);}catch(e){}})()`
	_ = chromedp.Run(ctx, chromedp.Evaluate(expr, nil))
}

// fillForms fills every form control with value, dispatches input/change so
// frameworks observe it, and requests submit — reaching flows behind input and
// submit handlers. It is only ever called in canary/confirm mode (observe never
// changes inputs).
func (s *domScanner) fillForms(ctx context.Context, value string) {
	js := `(function(v){try{
	  var forms=document.querySelectorAll('form');var n=0;
	  forms.forEach(function(f){
	    f.querySelectorAll('input,textarea').forEach(function(inp){
	      var t=(inp.type||'text').toLowerCase();
	      if(['hidden','submit','button','reset','image','file','checkbox','radio'].indexOf(t)!==-1)return;
	      try{inp.value=v;inp.dispatchEvent(new Event('input',{bubbles:true}));inp.dispatchEvent(new Event('change',{bubbles:true}));n++;}catch(e){}
	    });
	    try{if(typeof f.requestSubmit==='function')f.requestSubmit();else f.submit();}catch(e){}
	  });
	  // Also feed inputs that are not inside a form.
	  document.querySelectorAll('input,textarea').forEach(function(inp){
	    if(inp.form)return;var t=(inp.type||'text').toLowerCase();
	    if(['hidden','submit','button','reset','image','file','checkbox','radio'].indexOf(t)!==-1)return;
	    try{inp.value=v;inp.dispatchEvent(new Event('input',{bubbles:true}));inp.dispatchEvent(new Event('change',{bubbles:true}));}catch(e){}
	  });
	  return n;
	}catch(e){return 0;}})(` + jsString(value) + `)`
	_ = chromedp.Run(ctx, chromedp.Evaluate(js, nil), chromedp.Sleep(domInteractionSettle()))
}

// clickExplore clicks a bounded set of non-navigating controls to reveal
// event-gated state. It returns whether any control was clicked.
func (s *domScanner) clickExplore(ctx context.Context) bool {
	js := `(function(){try{
	  var sel='button,[role=button],[onclick],a[href^="#"],a[href^="javascript:"]';
	  var nodes=Array.prototype.slice.call(document.querySelectorAll(sel)).slice(0,25);
	  var n=0;nodes.forEach(function(el){try{el.click();n++;}catch(e){}});
	  return n;
	}catch(e){return 0;}})()`
	var n int
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &n), chromedp.Sleep(domInteractionSettle())); err != nil {
		return false
	}
	return n > 0
}

// sendWebMessage posts a message carrying value to the page (and its frames) so
// a message-driven flow is exercised.
func (s *domScanner) sendWebMessage(ctx context.Context, value string) {
	js := `(function(v){try{
	  var payloads=[v,{data:v},{message:v},{cmd:'render',payload:v},{type:'html',html:v}];
	  payloads.forEach(function(p){try{window.postMessage(p,'*');}catch(e){}});
	  for(var i=0;i<window.frames.length&&i<8;i++){try{window.frames[i].postMessage(v,'*');}catch(e){}}
	  return 1;
	}catch(e){return 0;}})(` + jsString(value) + `)`
	_ = chromedp.Run(ctx, chromedp.Evaluate(js, nil), chromedp.Sleep(domInteractionSettle()))
}

// inScopeNow reports whether the page's current origin is still within baseHost
// scope (or external probing is allowed).
func (s *domScanner) inScopeNow(ctx context.Context, baseHost string) bool {
	if s.cfg.AllowExternal {
		return true
	}
	var origin string
	if err := chromedp.Run(ctx, chromedp.Evaluate("location.origin", &origin)); err != nil {
		return true // cannot tell; do not falsely flag
	}
	if u, err := url.Parse(origin); err == nil && u.Hostname() != "" {
		return sameScope(baseHost, u.Hostname())
	}
	return true
}

// collectLinks returns the in-scope http(s) links present in the rendered DOM,
// used to extend the crawl. It never returns off-scope links unless external
// probing is allowed.
func (s *domScanner) collectLinks(ctx context.Context, baseHost string) ([]string, error) {
	if !s.cfg.Crawl {
		return nil, nil
	}
	var links []string
	js := `Array.prototype.slice.call(document.querySelectorAll('a[href]')).slice(0,500).map(function(a){return a.href;})`
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &links)); err != nil {
		return nil, nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, l := range links {
		u, err := url.Parse(l)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if !s.cfg.AllowExternal && !sameScope(baseHost, u.Hostname()) {
			continue
		}
		u.Fragment = ""
		key := u.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

// ---- canary construction ---------------------------------------------------

// buildCanaries derives the canary set for a page from its enabled sources,
// returning the canaries, the URL to navigate to (query/fragment canaries
// injected) and the referrer URL to set (empty when the referrer source is off).
func (s *domScanner) buildCanaries(pageURL string) (canaries []domCanary, injectedURL, referrer string) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, pageURL, ""
	}

	// URL query parameters: one distinct canary per existing parameter, so the
	// exact controlling parameter is identifiable even when several exist, plus a
	// synthetic parameter to catch code reading an arbitrary/added parameter.
	if s.sourceEnabled(SourceURLQuery) {
		q := u.Query()
		names := make([]string, 0, len(q))
		for name := range q {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			tok := randomCanary()
			q.Set(name, tok)
			canaries = append(canaries, domCanary{ID: SourceURLQuery + ":" + name, Token: tok, Kind: SourceURLQuery, Name: name})
		}
		tok := randomCanary()
		q.Set("jsmq", tok)
		canaries = append(canaries, domCanary{ID: SourceURLQuery + ":jsmq", Token: tok, Kind: SourceURLQuery, Name: "jsmq"})
		u.RawQuery = q.Encode()
	}

	// URL fragment: read only by client-side code, never sent to the server.
	if s.sourceEnabled(SourceURLFragment) {
		tok := randomCanary()
		u.Fragment = tok
		canaries = append(canaries, domCanary{ID: SourceURLFragment + ":fragment", Token: tok, Kind: SourceURLFragment, Name: "fragment"})
	}

	// JS-settable sources are seeded by the agent before page scripts run.
	for _, kind := range []string{SourceWindowName, SourceCookie, SourceLocalStorage, SourceSessionStorage} {
		if !s.sourceEnabled(kind) {
			continue
		}
		tok := randomCanary()
		name := ""
		switch kind {
		case SourceCookie:
			name = "jsmc"
		case SourceLocalStorage:
			name = "jsmls"
		case SourceSessionStorage:
			name = "jsmss"
		case SourceWindowName:
			name = "window.name"
		}
		canaries = append(canaries, domCanary{ID: kind + ":" + name, Token: tok, Kind: kind, Name: name})
	}

	injectedURL = u.String()

	// Referrer: set to an in-scope URL carrying the canary so document.referrer
	// reflects it without contacting any off-scope host.
	if s.sourceEnabled(SourceReferrer) {
		tok := randomCanary()
		ref := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/", RawQuery: "jsmref=" + tok}
		referrer = ref.String()
		canaries = append(canaries, domCanary{ID: SourceReferrer + ":referrer", Token: tok, Kind: SourceReferrer, Name: "referrer"})
	}

	return canaries, injectedURL, referrer
}

// injectSourceURL rebuilds pageURL with canary c injected into its URL-carried
// source (query/fragment). For JS-settable sources it returns the URL unchanged
// (the agent seeds those from c.Value).
func (s *domScanner) injectSourceURL(pageURL string, c domCanary) string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}
	val := c.Value
	if val == "" {
		val = c.Token
	}
	switch c.Kind {
	case SourceURLQuery:
		q := u.Query()
		q.Set(c.Name, val)
		u.RawQuery = q.Encode()
	case SourceURLFragment:
		u.Fragment = val
	}
	return u.String()
}

func (s *domScanner) formInputCanary() domCanary {
	tok := randomCanary()
	return domCanary{ID: SourceFormInput + ":input", Token: tok, Kind: SourceFormInput, Name: "input", Value: tok}
}

func (s *domScanner) webMessageCanary() domCanary {
	tok := randomCanary()
	return domCanary{ID: SourceWebMessage + ":message", Token: tok, Kind: SourceWebMessage, Name: "message", Value: tok}
}

// ---- ingest & classification ----------------------------------------------

// readAndIngest reads the agent state and ingests only the findings recorded
// since offset, tagging them with the given phase/trigger/interaction. Because
// the agent's findings array only grows within a page's browser context,
// ingesting the delta keeps each flow's trigger and phase precise rather than
// re-tagging earlier flows with every later pass's trigger. It returns the new
// offset (the total findings count) and the state read.
func (s *domScanner) readAndIngest(ctx context.Context, baseHost, pageURL, phase, trigger, interaction string, offset int) (int, domAgentState) {
	st, err := readAgentState(ctx)
	if err != nil {
		return offset, st
	}
	if len(st.Findings) > offset {
		s.ingestFindings(baseHost, pageURL, st.Findings[offset:], phase, trigger, interaction, st.Confirmations)
	}
	return len(st.Findings), st
}

// ingestFindings converts a batch of raw agent findings into DOMFindings,
// assigning severity/confidence and the scan context (target, phase, trigger),
// and appends them under the scanner lock.
func (s *domScanner) ingestFindings(baseHost, pageURL string, raw []domRawFinding, phase, trigger, interaction string, confirms map[string]bool) {
	if len(raw) == 0 {
		return
	}
	target := (&url.URL{Scheme: schemeOf(pageURL), Host: baseHost}).String()
	out := make([]DOMFinding, 0, len(raw))
	for _, rf := range raw {
		out = append(out, s.mapFinding(target, pageURL, rf, phase, trigger, interaction, confirms))
	}
	s.mu.Lock()
	s.findings = append(s.findings, out...)
	s.mu.Unlock()
}

// mapFinding turns one raw agent finding into a DOMFinding.
func (s *domScanner) mapFinding(target, pageURL string, rf domRawFinding, phase, trigger, interaction string, confirms map[string]bool) DOMFinding {
	f := DOMFinding{
		Target:       target,
		PageURL:      pageURL,
		FrameURL:     rf.FrameURL,
		FramePath:    rf.FramePath,
		ValuePreview: boundPreview(rf.Value),
		Context:      rf.Context,
		Stack:        toStackFrames(rf.Stack),
		Trigger:      trigger,
		Phase:        phase,
		Transform:    rf.Transform,
	}
	if f.FrameURL == "" {
		f.FrameURL = pageURL
	}
	switch rf.Kind {
	case "flow":
		f.Type = DOMTypeFlow
		f.Sink = &DOMSink{Name: rf.Sink, Argument: rf.Argument}
		f.Source = &DOMSource{Kind: rf.SourceKind, Name: rf.SourceName}
		f.ProbeID = rf.ProbeID
		if interaction != "" && trigger != TriggerPageLoad {
			f.Interaction = interaction
		}
		confirmed := rf.ProbeID != "" && confirms[rf.ProbeID]
		f.Confirmed = confirmed
		f.Severity, f.Confidence = classifyFlow(rf.Context, confirmed)
	case "sink":
		f.Type = DOMTypeSink
		f.Sink = &DOMSink{Name: rf.Sink, Argument: rf.Argument}
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceMedium
	case "message":
		f.Type = DOMTypeWebMessage
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceMedium
		if rf.Message != nil {
			f.Message = &DOMMessageInfo{
				ListenerCount: rf.Message.ListenerCount,
				OriginChecked: rf.Message.OriginChecked,
				SourceChecked: rf.Message.SourceChecked,
				DataShape:     rf.Message.DataShape,
				ReachesSink:   rf.Message.ReachesSink,
				SentToOrigin:  rf.Message.SentToOrigin,
				Identity:      rf.Message.Identity,
			}
			if rf.Message.SentToOrigin != "" {
				// A cross-origin send of URL-derived data is a low-severity leak, not
				// merely informational.
				f.Severity = SeverityLow
			}
		}
	default:
		f.Type = DOMTypeSink
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceLow
	}
	f.Fingerprint = f.computeFingerprint()
	return f
}

// classifyFlow maps a sink parse context (and whether execution was confirmed)
// to a severity/confidence pair, keeping the two axes separate.
func classifyFlow(sinkContext string, confirmed bool) (severity, confidence string) {
	if confirmed {
		return SeverityHigh, ConfidenceCertain
	}
	switch sinkContext {
	case "js", "script-url":
		return SeverityHigh, ConfidenceHigh
	case "html":
		return SeverityMedium, ConfidenceHigh
	case "attribute":
		return SeverityMedium, ConfidenceHigh
	case "url":
		return SeverityLow, ConfidenceHigh
	default:
		return SeverityLow, ConfidenceMedium
	}
}

// confirmFlows marks every recorded flow bearing probe id pid as confirmed
// execution (high severity, certain confidence).
func (s *domScanner) confirmFlows(pid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.findings {
		if s.findings[i].Type == DOMTypeFlow && s.findings[i].ProbeID == pid {
			s.findings[i].Confirmed = true
			s.findings[i].Severity = SeverityHigh
			s.findings[i].Confidence = ConfidenceCertain
		}
	}
}

// ---- agent config, counters & bookkeeping ----------------------------------

func (s *domScanner) agentConfig(mode, relay string, canaries []domCanary) domAgentConfig {
	return domAgentConfig{
		Mode:     mode,
		Token:    relay,
		Canaries: canaries,
		Messages: s.cfg.Messages,
		Sinks:    s.cfg.Sinks,
		Limits:   domAgentLimits{MaxFindings: 300, PreviewMax: 120, StackDepth: 8},
	}
}

func (s *domScanner) sourceEnabled(kind string) bool {
	if s.cfg.Sources == nil {
		return true
	}
	return s.cfg.Sources[kind]
}

// reservePage records a page as visited and reserves it against MaxPages,
// returning false if it was already visited or the page budget is spent.
func (s *domScanner) reservePage(pageURL string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.visited[pageURL]; ok {
		return false
	}
	if s.cfg.MaxPages > 0 && len(s.visited) >= s.cfg.MaxPages {
		s.partial = true
		return false
	}
	s.visited[pageURL] = struct{}{}
	return true
}

// reserveProbes atomically reserves n probes against MaxProbes, returning false
// (and marking the scan partial) when the budget would be exceeded, so a page
// or application can never drive unbounded probes.
func (s *domScanner) reserveProbes(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxProbes > 0 && s.probes+n > s.cfg.MaxProbes {
		s.partial = true
		return false
	}
	s.probes += n
	return true
}

func (s *domScanner) budgetExhausted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxPages > 0 && len(s.visited) >= s.cfg.MaxPages {
		return true
	}
	if s.cfg.MaxProbes > 0 && s.probes >= s.cfg.MaxProbes {
		return true
	}
	return false
}

func (s *domScanner) pageDone() {
	s.mu.Lock()
	s.pagesScanned++
	s.mu.Unlock()
}

func (s *domScanner) pageFailed(msg string) {
	s.mu.Lock()
	s.pagesFailed++
	s.errs = append(s.errs, msg)
	s.mu.Unlock()
}

func (s *domScanner) addErr(msg string) {
	s.mu.Lock()
	s.errs = append(s.errs, msg)
	s.mu.Unlock()
}

// note attaches a diagnostic annotation to a page's most recent findings and
// records it as a scan-level note, so partial or instrumentation-broken pages
// are clearly reported.
func (s *domScanner) note(pageURL, msg string) {
	s.mu.Lock()
	s.errs = append(s.errs, pageURL+": "+msg)
	s.partial = true
	s.mu.Unlock()
	if s.cfg.Progress != nil {
		s.cfg.Progress("[dom] " + pageURL + ": " + msg)
	}
}

func (s *domScanner) snapshotFindings() []DOMFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DOMFinding, len(s.findings))
	copy(out, s.findings)
	return out
}

func (s *domScanner) buildSummary(cfg DOMScanConfig, findingCount int, findings []DOMFinding, dur time.Duration) DOMScanSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySev := map[string]int{SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, f := range findings {
		bySev[strings.ToLower(f.Severity)]++
	}
	return DOMScanSummary{
		SchemaVersion:      DOMSchemaVersion,
		Mode:               cfg.Mode,
		PagesScanned:       s.pagesScanned,
		PagesFailed:        s.pagesFailed,
		ProbesSent:         s.probes,
		ProbesLimit:        cfg.MaxProbes,
		MaxPages:           cfg.MaxPages,
		Findings:           findingCount,
		FindingsBySeverity: bySev,
		Partial:            s.partial || s.pagesFailed > 0,
		TimedOut:           s.timedOut,
		DurationMS:         dur.Milliseconds(),
		Errors:             append([]string(nil), s.errs...),
	}
}

// ---- small utilities -------------------------------------------------------

// domSettle is the initial per-page settle wait, reusing the render sleep so the
// -timeout flag governs it, but capped so a long render sleep does not blow the
// per-page DOM budget.
func domSettle() time.Duration {
	d := RenderSleepDuration
	if d > 6*time.Second {
		d = 6 * time.Second
	}
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

func domInteractionSettle() time.Duration { return 800 * time.Millisecond }

func brokeExecution(st domAgentState) bool { return st.HookErrors > 5 }

func toStackFrames(raw []domRawFrame) []DOMStackFrame {
	if len(raw) == 0 {
		return nil
	}
	out := make([]DOMStackFrame, 0, len(raw))
	for _, r := range raw {
		out = append(out, DOMStackFrame{Function: r.Function, URL: r.URL, Line: r.Line, Column: r.Column})
	}
	return out
}

// boundPreview caps a value preview defensively on the Go side too, so output
// can never grow without limit even if the agent's bound were bypassed.
func boundPreview(v string) string {
	const max = 160
	if len(v) > max {
		return v[:max] + "…"
	}
	return v
}

func schemeOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Scheme != "" {
		return u.Scheme
	}
	return "https"
}

// randomCanary returns a unique, non-executing marker for a source. The fixed
// prefix makes matches unmistakable and the random suffix makes each probe's
// identity unique.
func randomCanary() string { return "jsmdomc" + randomToken() }

// randomToken returns a random lowercase-hex token.
func randomToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// confirmMarker is the stable substring embedded in a confirm payload so the
// resulting sink hit is still attributed to the probe.
func confirmMarker(pid string) string {
	return "jsmdomk" + shortHash(pid)
}

func shortHash(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

// confirmPayload builds a controlled, non-visible execution probe for a sink
// context. It never uses a visible dialog: a fired payload calls the hidden
// __jsmdomConfirm beacon. The embedded confirm marker also lets the flow be
// attributed by the canary matcher.
func confirmPayload(sinkContext, pid string) string {
	marker := confirmMarker(pid)
	switch sinkContext {
	case "html":
		// The marker rides along as the img source so the flow is still attributed;
		// the error handler fires the hidden beacon when the markup is parsed.
		return `<img src="` + marker + `" onerror="window.__jsmdomConfirm&&window.__jsmdomConfirm('` + pid + `')">`
	case "js":
		return `/*` + marker + `*/;try{window.__jsmdomConfirm&&window.__jsmdomConfirm('` + pid + `')}catch(e){};//`
	default:
		return marker
	}
}

// jsString renders s as a safe JS string literal for embedding in an evaluated
// expression.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
