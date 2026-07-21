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

	// SourceHints are parameter/storage/cookie names mined by the static crawl or
	// passive indexes. MaxSourceHintsPerPage bounds how many are applied to one
	// rendered route; zero selects the default rather than removing the bound.
	SourceHints           []DOMSourceHint
	MaxSourceHintsPerPage int

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
		Mode:                  DOMModeCanary,
		MaxPages:              50,
		MaxProbes:             1000,
		Workers:               4,
		PageTimeout:           25 * time.Second,
		Messages:              true,
		MaxDepth:              2,
		MaxSourceHintsPerPage: 100,
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
	SourceHints        int            `json:"source_hints"`
	HintProbesSent     int            `json:"hint_probes_sent"`
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
	hintProbes   int
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
	canaries, injectedURL, referrer := s.buildCanaries(pageURL, s.probeCapacity())
	if len(canaries) == 0 {
		return s.runObserve(ctx, baseHost, pageURL, relay)
	}
	if !s.reserveProbes(len(canaries)) {
		// Probe budget exhausted before this page: fall back to a pure observation
		// so the page is still not wasted, but inject nothing.
		return s.runObserve(ctx, baseHost, pageURL, relay)
	}
	s.noteHintProbes(canaries)

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

	// Interaction pass: give each real form field its own canary, then submit and
	// click controls to reach event-triggered and delayed flows. Per-field identity
	// avoids the old ambiguity where every input was reported simply as "input".
	if s.sourceEnabled(SourceFormInput) {
		var formCanaries []domCanary
		for _, fic := range s.formInputCanaries(ctx) {
			if !s.reserveProbes(1) {
				break
			}
			canaries = append(canaries, fic)
			formCanaries = append(formCanaries, fic)
			s.addCanaryToAgent(ctx, fic)
		}
		s.fillFormCanaries(ctx, formCanaries)
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
			s.fillFormField(ctx, k.name, payload)
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

func (s *domScanner) formInputCanaries(ctx context.Context) []domCanary {
	js := `(function(){try{
	  var nodes=Array.prototype.slice.call(document.querySelectorAll('input,textarea'));
	  var seen={},out=[];
	  nodes.forEach(function(el,i){
	    var t=(el.type||'text').toLowerCase();
	    if(['hidden','submit','button','reset','image','file','checkbox','radio'].indexOf(t)!==-1)return;
	    var k=el.getAttribute('name')||el.id||('field_'+i);
	    if(!seen[k]){seen[k]=1;out.push(k);}
	  });
	  return out.slice(0,100);
	}catch(e){return [];}})()`
	var names []string
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &names)); err != nil {
		return nil
	}
	maxFields := s.cfg.MaxSourceHintsPerPage
	if maxFields <= 0 || maxFields > 100 {
		maxFields = 100
	}
	if len(names) > maxFields {
		names = names[:maxFields]
	}
	out := make([]domCanary, 0, len(names))
	for _, name := range names {
		if !validDOMSourceHintName(name) {
			continue
		}
		tok := randomCanary()
		out = append(out, domCanary{
			ID: SourceFormInput + ":" + name, Token: tok, Kind: SourceFormInput,
			Name: name, Value: tok, DiscoveredBy: []string{DOMHintDOMForm},
		})
	}
	return out
}

// fillFormCanaries fills each field with its unique value, dispatches the events
// frameworks listen for, and submits each containing form once.
func (s *domScanner) fillFormCanaries(ctx context.Context, canaries []domCanary) {
	if len(canaries) == 0 {
		return
	}
	values := make(map[string]string, len(canaries))
	for _, canary := range canaries {
		values[canary.Name] = canary.Value
	}
	data, err := json.Marshal(values)
	if err != nil {
		return
	}
	js := `(function(values){try{
	  var nodes=Array.prototype.slice.call(document.querySelectorAll('input,textarea'));var n=0,forms=[];
	  nodes.forEach(function(el,i){
	    var t=(el.type||'text').toLowerCase();
	    if(['hidden','submit','button','reset','image','file','checkbox','radio'].indexOf(t)!==-1)return;
	    var k=el.getAttribute('name')||el.id||('field_'+i);if(!Object.prototype.hasOwnProperty.call(values,k))return;
	    try{el.value=values[k];el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));n++;if(el.form&&forms.indexOf(el.form)<0)forms.push(el.form);}catch(e){}
	  });
	  forms.forEach(function(f){try{
	    f.addEventListener('submit',function(ev){ev.preventDefault();},{capture:true,once:true});
	    if(typeof f.requestSubmit==='function')f.requestSubmit();
	    else f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
	  }catch(e){}});
	  return n;
	}catch(e){return 0;}})(` + string(data) + `)`
	_ = chromedp.Run(ctx, chromedp.Evaluate(js, nil), chromedp.Sleep(domInteractionSettle()))
}

func (s *domScanner) fillFormField(ctx context.Context, name, value string) {
	data, err := json.Marshal(map[string]string{name: value})
	if err != nil {
		return
	}
	js := `(function(values){try{
	  var nodes=Array.prototype.slice.call(document.querySelectorAll('input,textarea'));var forms=[];
	  nodes.forEach(function(el,i){var k=el.getAttribute('name')||el.id||('field_'+i);if(!Object.prototype.hasOwnProperty.call(values,k))return;
	    try{el.value=values[k];el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));if(el.form&&forms.indexOf(el.form)<0)forms.push(el.form);}catch(e){}});
	  forms.forEach(function(f){try{f.addEventListener('submit',function(ev){ev.preventDefault();},{capture:true,once:true});if(typeof f.requestSubmit==='function')f.requestSubmit();else f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));}catch(e){}});return 1;
	}catch(e){return 0;}})(` + string(data) + `)`
	_ = chromedp.Run(ctx, chromedp.Evaluate(js, nil), chromedp.Sleep(domInteractionSettle()))
}

// clickExplore clicks a bounded set of non-navigating controls to reveal
// event-gated state. It returns whether any control was clicked.
func (s *domScanner) clickExplore(ctx context.Context) bool {
	js := `(function(){try{
	  var sel='button,[role=button],[onclick],a[href^="#"],a[href^="javascript:"]';
	  var nodes=Array.prototype.slice.call(document.querySelectorAll(sel)).slice(0,25);
	  var n=0;nodes.forEach(function(el){try{
	    var tag=(el.tagName||'').toLowerCase(),type=(el.getAttribute&&el.getAttribute('type')||'').toLowerCase();
	    if(tag==='button'&&(type===''||type==='submit'||type==='reset'))return;
	    el.click();n++;
	  }catch(e){}});
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
	  if(window.__jsmdom)window.__jsmdom.sendingProbe=true;
	  var payloads=[v,{data:v},{message:v},{cmd:'render',payload:v},{type:'html',html:v}];
	  payloads.forEach(function(p){try{window.postMessage(p,'*');}catch(e){}});
	  for(var i=0;i<window.frames.length&&i<8;i++){try{window.frames[i].postMessage(v,'*');}catch(e){}}
	  if(window.__jsmdom)window.__jsmdom.sendingProbe=false;
	  return 1;
	}catch(e){try{if(window.__jsmdom)window.__jsmdom.sendingProbe=false;}catch(x){}return 0;}})(` + jsString(value) + `)`
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
const domMaxInjectedURLLength = 16 << 10

func (s *domScanner) buildCanaries(pageURL string, maxCanaries int) (canaries []domCanary, injectedURL, referrer string) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, pageURL, ""
	}

	seen := make(map[string]bool)
	hasCapacity := func() bool { return maxCanaries < 0 || len(canaries) < maxCanaries }
	mergeDiscovery := func(kind, name string, discovered []string) bool {
		id := kind + ":" + name
		for i := range canaries {
			if canaries[i].ID == id {
				canaries[i].DiscoveredBy = uniqueSortedStrings(append(canaries[i].DiscoveredBy, discovered...))
				return true
			}
		}
		return false
	}
	add := func(kind, name string, discovered []string) (domCanary, bool) {
		key := kind + "\x1f" + name
		if seen[key] {
			mergeDiscovery(kind, name, discovered)
			return domCanary{}, false
		}
		if !hasCapacity() {
			return domCanary{}, false
		}
		seen[key] = true
		tok := randomCanary()
		c := domCanary{
			ID: kind + ":" + name, Token: tok, Kind: kind, Name: name,
			DiscoveredBy: uniqueSortedStrings(discovered),
		}
		canaries = append(canaries, c)
		return c, true
	}

	q := u.Query()
	setQueryCanary := func(name string, discovered []string, enforceLength bool) bool {
		if seen[SourceURLQuery+"\x1f"+name] {
			mergeDiscovery(SourceURLQuery, name, discovered)
			return false
		}
		if !hasCapacity() {
			return false
		}
		tok := randomCanary()
		if enforceLength {
			trial := cloneURLValues(q)
			trial.Set(name, tok)
			candidate := *u
			candidate.RawQuery = trial.Encode()
			if len(candidate.String()) > domMaxInjectedURLLength {
				return false
			}
		}
		q.Set(name, tok)
		seen[SourceURLQuery+"\x1f"+name] = true
		canaries = append(canaries, domCanary{
			ID: SourceURLQuery + ":" + name, Token: tok, Kind: SourceURLQuery, Name: name,
			DiscoveredBy: uniqueSortedStrings(discovered),
		})
		return true
	}

	// URL query parameters already present on the route retain first priority.
	if s.sourceEnabled(SourceURLQuery) {
		names := make([]string, 0, len(q))
		for name := range q {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			setQueryCanary(name, []string{"page_url"}, false)
		}
	}

	// Static/passive names are tried on every same-scope route. Direct JavaScript
	// access evidence ranks before request-body and passive archive hints.
	hints := s.sourceHintsForPage(u.Hostname())
	maxHints := s.cfg.MaxSourceHintsPerPage
	if maxHints <= 0 {
		maxHints = DefaultDOMScanConfig().MaxSourceHintsPerPage
	}
	usedHints := 0
	for _, hint := range hints {
		if usedHints >= maxHints {
			break
		}
		if !s.sourceEnabled(hint.Kind) {
			continue
		}
		if seen[hint.Kind+"\x1f"+hint.Name] {
			mergeDiscovery(hint.Kind, hint.Name, hint.Discovered)
			usedHints++
			continue
		}
		var added bool
		if hint.Kind == SourceURLQuery {
			added = setQueryCanary(hint.Name, hint.Discovered, true)
		} else {
			_, added = add(hint.Kind, hint.Name, hint.Discovered)
		}
		if added {
			usedHints++
		}
	}

	// Keep a generic added parameter after real names so arbitrary-query readers
	// are still detected without displacing higher-value intelligence.
	if s.sourceEnabled(SourceURLQuery) {
		setQueryCanary("jsmq", []string{"synthetic"}, true)
		u.RawQuery = q.Encode()
	}

	// URL fragment: read only by client-side code, never sent to the server.
	if s.sourceEnabled(SourceURLFragment) {
		if c, ok := add(SourceURLFragment, "fragment", []string{"synthetic"}); ok {
			u.Fragment = c.Token
		}
	}

	// JS-settable sources are seeded by the agent before page scripts run.
	for _, kind := range []string{SourceWindowName, SourceCookie, SourceLocalStorage, SourceSessionStorage} {
		if !s.sourceEnabled(kind) {
			continue
		}
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
		add(kind, name, []string{"synthetic"})
	}

	injectedURL = u.String()

	// Referrer: set to an in-scope URL carrying the canary so document.referrer
	// reflects it without contacting any off-scope host.
	if s.sourceEnabled(SourceReferrer) {
		if c, ok := add(SourceReferrer, "referrer", []string{"synthetic"}); ok {
			ref := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/", RawQuery: "jsmref=" + c.Token}
			referrer = ref.String()
		}
	}

	return canaries, injectedURL, referrer
}

func cloneURLValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (s *domScanner) sourceHintsForPage(host string) []DOMSourceHint {
	byKey := make(map[string]DOMSourceHint)
	for _, hint := range s.cfg.SourceHints {
		if !validDOMSourceHintName(hint.Name) {
			continue
		}
		if hint.ScopeHost != "" && !sameScope(hint.ScopeHost, host) {
			continue
		}
		hint.ScopeHost = "" // scope has been enforced; merge identical page hints
		mergeDOMSourceHint(byKey, hint)
	}
	hints := make([]DOMSourceHint, 0, len(byKey))
	for _, hint := range byKey {
		hints = append(hints, hint)
	}
	sort.SliceStable(hints, func(i, j int) bool {
		pi, pj := domHintPriority(hints[i]), domHintPriority(hints[j])
		if pi != pj {
			return pi < pj
		}
		if hints[i].Kind != hints[j].Kind {
			return hints[i].Kind < hints[j].Kind
		}
		return hints[i].Name < hints[j].Name
	})
	return hints
}

func domHintPriority(hint DOMSourceHint) int {
	for _, source := range hint.Discovered {
		if source == DOMHintJavaScriptAccess {
			return 0
		}
	}
	for _, source := range hint.Discovered {
		if source == DOMHintJavaScriptURL || source == DOMHintJavaScriptRequest {
			return 1
		}
	}
	return 2
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
		f.Source = &DOMSource{Kind: rf.SourceKind, Name: rf.SourceName, DiscoveredBy: uniqueSortedStrings(rf.Discovered)}
		f.ProbeID = rf.ProbeID
		if rf.URL != nil {
			f.URL = &DOMURLEvidence{
				Resolved:          rf.URL.Resolved,
				Scheme:            rf.URL.Scheme,
				DestinationOrigin: rf.URL.DestinationOrigin,
				SameOrigin:        rf.URL.SameOrigin,
				CanaryComponent:   rf.URL.CanaryComponent,
				InputKind:         rf.URL.InputKind,
				ExecutableScheme:  rf.URL.ExecutableScheme,
			}
		}
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
				ListenerCount:          rf.Message.ListenerCount,
				OriginChecked:          rf.Message.OriginChecked,
				OriginCheckedListeners: rf.Message.OriginCheckedListeners,
				SourceChecked:          rf.Message.SourceChecked,
				SourceCheckedListeners: rf.Message.SourceCheckedListeners,
				DataShape:              rf.Message.DataShape,
				ReachesSink:            rf.Message.ReachesSink,
				ProbeGenerated:         rf.Message.ProbeGenerated,
				SentToOrigin:           rf.Message.SentToOrigin,
				Identity:               rf.Message.Identity,
				ListenerLocations:      toStackFrames(rf.Message.ListenerLocations),
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
	f.Triage = assessDOMFinding(f)
	f.Fingerprint = f.computeFingerprint()
	return f
}

// assessDOMFinding turns the evidence already gathered for a finding into a
// conservative triage hint. It deliberately avoids claiming exploitability:
// only controlled execution is labelled confirmed.
func assessDOMFinding(f DOMFinding) *DOMTriage {
	if f.Confirmed {
		return &DOMTriage{Verdict: DOMTriageConfirmed, Reason: "controlled execution was confirmed"}
	}
	if f.Type == DOMTypeWebMessage && f.Message != nil {
		switch {
		case f.Message.ReachesSink:
			return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "message data reached a security-sensitive sink"}
		case f.Message.SentToOrigin != "":
			return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "URL-derived data was sent to a cross-origin message target"}
		case f.Message.ProbeGenerated:
			return &DOMTriage{Verdict: DOMTriageLikelyBenign, Reason: "scanner probe was observed, but its data did not reach a security-sensitive sink"}
		case f.Message.ListenerCount > 0 && !f.Message.OriginChecked:
			return &DOMTriage{Verdict: DOMTriageLikelyBenign, Reason: "no origin inspection was visible, but no security-sensitive effect was observed"}
		default:
			return &DOMTriage{Verdict: DOMTriageInfo, Reason: "message activity was observed without a security-sensitive effect"}
		}
	}
	if f.Type == DOMTypeFlow {
		switch f.Context {
		case "js", "script-url":
			return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "controllable data reached a JavaScript execution context"}
		case "html", "attribute":
			return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "controllable data reached a markup-capable context; execution was not confirmed"}
		case "url":
			if f.URL == nil || !f.URL.Resolved {
				return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "controllable data reached a navigation target whose destination could not be classified"}
			}
			if f.URL.ExecutableScheme {
				return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "navigation resolved to an executable URL scheme; execution was not confirmed"}
			}
			if !f.URL.SameOrigin {
				return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "controllable data reached a cross-origin navigation target"}
			}
			if f.URL.CanaryComponent == "query" || f.URL.CanaryComponent == "fragment" {
				return &DOMTriage{Verdict: DOMTriageLikelyBenign, Reason: "direct destination stayed same-origin and the marker remained in the URL " + f.URL.CanaryComponent}
			}
			return &DOMTriage{Verdict: DOMTriageLikelyBenign, Reason: "direct destination stayed same-origin and no executable scheme was observed"}
		default:
			return &DOMTriage{Verdict: DOMTriageWorthReview, Reason: "controllable data reached a security-sensitive browser API"}
		}
	}
	return &DOMTriage{Verdict: DOMTriageInfo, Reason: "sink activity was observed without evidence of attacker control"}
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
			s.findings[i].Triage = assessDOMFinding(s.findings[i])
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

// probeCapacity snapshots the remaining global canary budget. A negative value
// means unlimited. Concurrent workers still reserve atomically afterwards; the
// snapshot mainly prevents one late page from constructing a canary set that
// can never fit and unnecessarily falling all the way back to observe mode.
func (s *domScanner) probeCapacity() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxProbes <= 0 {
		return -1
	}
	left := s.cfg.MaxProbes - s.probes
	if left < 0 {
		return 0
	}
	return left
}

func (s *domScanner) noteHintProbes(canaries []domCanary) {
	n := 0
	for _, canary := range canaries {
		for _, source := range canary.DiscoveredBy {
			if source != "synthetic" && source != "page_url" {
				n++
				break
			}
		}
	}
	if n == 0 {
		return
	}
	s.mu.Lock()
	s.hintProbes += n
	s.mu.Unlock()
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
		SourceHints:        len(cfg.SourceHints),
		HintProbesSent:     s.hintProbes,
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
