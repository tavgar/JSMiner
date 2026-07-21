package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The DOM scanner drives a real headless Chrome, so these tests need a browser.
// They use only local, deliberately-vulnerable pages (never a public target) and
// are skipped when no Chrome/Chromium is available. Run the whole set with:
//
//	go test ./internal/scan/ -run TestDOM -v
//
// They tune the render waits down and pin browser resolution to a
// cached/PATH build so no network access is required.

// domTestSetup shortens render waits, pins the browser and resets the throttle,
// returning a restore func. It skips the test when no browser is present.
func domTestSetup(t *testing.T) func() {
	t.Helper()
	if !chromeAvailable() {
		t.Skip("DOM live test: no Chrome/Chromium binary found on PATH")
	}
	savedSleep, savedTimeout := RenderSleepDuration, RenderTimeout
	RenderSleepDuration = 500 * time.Millisecond
	RenderTimeout = 15 * time.Second
	savedAuto := AutoDownloadBrowser
	AutoDownloadBrowser = false
	resetResolvedBrowser()
	ResetThrottle()
	return func() {
		RenderSleepDuration, RenderTimeout = savedSleep, savedTimeout
		AutoDownloadBrowser = savedAuto
		resetResolvedBrowser()
	}
}

// vulnServer serves a set of deliberately-vulnerable DOM XSS pages.
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<!doctype html><html><head><title>t</title></head><body>"+body+"</body></html>")
		}
	}

	// query parameter -> innerHTML (dangerous HTML sink)
	mux.HandleFunc("/innerhtml", page(`<div id=out></div>
<script>
  var q = new URLSearchParams(location.search).get('q');
  document.getElementById('out').innerHTML = 'Hello ' + (q||'');
</script>`))

	// URL fragment -> eval (JS execution sink)
	mux.HandleFunc("/fragment", page(`<div id=out></div>
<script>
  var h = decodeURIComponent(location.hash.slice(1));
  if (h) { try { eval(h); } catch (e) {} }
</script>`))

	// several parameters, only 'b' is used
	mux.HandleFunc("/multi", page(`<div id=out></div>
<script>
  var b = new URLSearchParams(location.search).get('b');
  document.getElementById('out').innerHTML = b || '';
</script>`))

	// a dangerous sink fed only static data (no source flows into it)
	mux.HandleFunc("/safe", page(`<div id=out></div>
<script>document.getElementById('out').innerHTML = 'static safe content';</script>`))

	// delayed / event-triggered: hash -> innerHTML on click, after a timer
	mux.HandleFunc("/delayed", page(`<button id=go>go</button><div id=out></div>
<script>
  document.getElementById('go').addEventListener('click', function(){
    setTimeout(function(){ document.getElementById('out').innerHTML = location.hash.slice(1); }, 80);
  });
</script>`))

	// a same-origin frame whose child reads window.name into innerHTML
	mux.HandleFunc("/frame", page(`<iframe src="/framechild"></iframe>`))
	mux.HandleFunc("/framechild", page(`<div id=out></div>
<script>document.getElementById('out').innerHTML = window.name || '';</script>`))

	// postMessage -> innerHTML with no origin check
	mux.HandleFunc("/pm", page(`<div id=out></div>
<script>
  window.addEventListener('message', function(e){
    document.getElementById('out').innerHTML = e.data;
  });
</script>`))

	// postMessage listener that inspects origin (evidence of inspection only)
	mux.HandleFunc("/pm-origin", page(`<div id=out></div>
<script>
  window.addEventListener('message', function(e){
    if (e.origin !== 'https://trusted.example') return;
    document.getElementById('out').innerHTML = e.data;
  });
</script>`))

	// current URL -> anchor.href: ordinary same-origin URL propagation used to
	// verify that URL evidence can separate a benign-looking link rewrite from a
	// cross-origin or executable destination.
	mux.HandleFunc("/href", page(`<a id=out>current</a>
<script>document.getElementById('out').href = location.href;</script>`))

	// A parameter name that exists only in JavaScript. The seed URL has no query,
	// so this flow is reachable only when static source hints feed the DOM pass.
	mux.HandleFunc("/hinted-eval", page(`<script>
  var p = new URLSearchParams(location.search).get('dom_payload');
  if (p) { try { eval(p); } catch (e) {} }
</script>`))

	// Two fields drive separate sinks; unique form canaries must identify which
	// field reached which sink instead of reporting the old generic "input".
	mux.HandleFunc("/form-fields", page(`<form><input name=title><textarea name=body></textarea></form><div id=out></div>
<script>
  document.querySelector('[name=body]').addEventListener('input', function(e){
    document.getElementById('out').innerHTML=e.target.value;
  });
</script>`))

	// localStorage -> innerHTML (sensitive source; only our marker is ever seeded)
	mux.HandleFunc("/storage", page(`<div id=out></div>
<script>document.getElementById('out').innerHTML = localStorage.getItem('jsmls') || '';</script>`))

	// a hub linking to many pages, for page/probe-limit tests
	var links strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&links, `<a href="/innerhtml?q=%d">p%d</a> `, i, i)
	}
	mux.HandleFunc("/hub", page(links.String()))

	return httptest.NewServer(mux)
}

func runDOM(t *testing.T, target string, mut func(*DOMScanConfig)) DOMScanResult {
	t.Helper()
	cfg := DefaultDOMScanConfig()
	cfg.Workers = 1
	cfg.MaxPages = 5
	cfg.PageTimeout = 15 * time.Second
	if mut != nil {
		mut(&cfg)
	}
	e := NewExtractor(false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := e.ScanDOM(ctx, []string{target}, cfg)
	if err != nil {
		t.Fatalf("ScanDOM(%s): %v", target, err)
	}
	return res
}

// findFlow returns the first flow finding matching the source kind/name and sink
// substring, or nil.
func findFlow(res DOMScanResult, sourceKind, sourceName, sinkSub string) *DOMFinding {
	for i := range res.Findings {
		f := res.Findings[i]
		if f.Type != DOMTypeFlow || f.Source == nil || f.Sink == nil {
			continue
		}
		if f.Source.Kind != sourceKind {
			continue
		}
		if sourceName != "" && f.Source.Name != sourceName {
			continue
		}
		if sinkSub != "" && !strings.Contains(f.Sink.Name, sinkSub) {
			continue
		}
		return &res.Findings[i]
	}
	return nil
}

func TestDOMQueryToInnerHTML(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/innerhtml?q=hello", nil)
	f := findFlow(res, SourceURLQuery, "q", "innerHTML")
	if f == nil {
		t.Fatalf("no url_query[q] -> innerHTML flow found; findings=%s", summarize(res))
	}
	if f.Severity != SeverityMedium {
		t.Errorf("html sink flow severity = %q, want medium", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("unique canary flow confidence = %q, want high", f.Confidence)
	}
	if f.Context != "html" {
		t.Errorf("context = %q, want html", f.Context)
	}
}

func TestDOMFragmentToEval(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/fragment", nil)
	f := findFlow(res, SourceURLFragment, "", "eval")
	if f == nil {
		t.Fatalf("no url_fragment -> eval flow found; findings=%s", summarize(res))
	}
	if f.Severity != SeverityHigh {
		t.Errorf("js execution sink flow severity = %q, want high", f.Severity)
	}
}

func TestDOMNoReportWhenCanaryAbsent(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/safe?q=x", nil)
	for _, f := range res.Findings {
		if f.Type == DOMTypeFlow {
			t.Errorf("unexpected flow reported for a static sink: %+v", f)
		}
	}
}

func TestDOMIdentifiesCorrectParameter(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/multi?a=1&b=2&c=3", nil)
	if findFlow(res, SourceURLQuery, "b", "innerHTML") == nil {
		t.Fatalf("did not attribute the flow to parameter 'b'; findings=%s", summarize(res))
	}
	for _, bad := range []string{"a", "c", "jsmq"} {
		if f := findFlow(res, SourceURLQuery, bad, "innerHTML"); f != nil {
			t.Errorf("misattributed flow to parameter %q: %+v", bad, f)
		}
	}
}

func TestDOMRecordsStackEvidence(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/innerhtml?q=hello", nil)
	f := findFlow(res, SourceURLQuery, "q", "innerHTML")
	if f == nil {
		t.Fatalf("no flow to inspect; findings=%s", summarize(res))
	}
	if len(f.Stack) == 0 || f.Stack[0].URL == "" {
		t.Fatalf("flow lacks usable stack evidence: %+v", f.Stack)
	}
	if !strings.HasPrefix(f.Stack[0].URL, "http") {
		t.Errorf("stack frame URL is not a real script location: %q", f.Stack[0].URL)
	}
}

func TestDOMDelayedEventTriggeredFlow(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/delayed", nil)
	if findFlow(res, SourceURLFragment, "", "innerHTML") == nil {
		t.Fatalf("delayed/event-triggered fragment -> innerHTML flow not detected; findings=%s", summarize(res))
	}
}

func TestDOMFlowInsideFrame(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/frame", nil)
	f := findFlow(res, SourceWindowName, "", "innerHTML")
	if f == nil {
		t.Fatalf("no window_name -> innerHTML flow inside frame; findings=%s", summarize(res))
	}
	if !strings.Contains(f.FrameURL, "/framechild") {
		t.Errorf("flow not attributed to the child frame: frame_url=%q", f.FrameURL)
	}
}

func TestDOMPostMessageToSink(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/pm", nil)
	if findFlow(res, SourceWebMessage, "", "innerHTML") == nil {
		t.Fatalf("postMessage data -> innerHTML flow not detected; findings=%s", summarize(res))
	}
	// A web_message finding should record the listener without an origin check.
	var msg *DOMMessageInfo
	for i := range res.Findings {
		if res.Findings[i].Message != nil && res.Findings[i].Message.SentToOrigin != "" && res.Findings[i].Message.ProbeGenerated {
			t.Errorf("scanner probe was misreported as an application data leak: %+v", res.Findings[i].Message)
		}
		if msg == nil && res.Findings[i].Type == DOMTypeWebMessage && res.Findings[i].Message != nil && res.Findings[i].Message.ListenerCount > 0 {
			msg = res.Findings[i].Message
		}
	}
	if msg == nil {
		t.Fatalf("no web_message listener finding; findings=%s", summarize(res))
	}
	if msg.OriginChecked {
		t.Error("listener that does not read event.origin reported as origin-checked")
	}
	if !msg.ReachesSink {
		t.Error("message observation was not correlated with its source-to-sink flow")
	}
	if !msg.ProbeGenerated {
		t.Error("scanner-generated message was not labelled as a probe")
	}
	if len(msg.ListenerLocations) == 0 {
		t.Error("message listener registration location was not captured")
	}
}

func TestDOMURLFlowIncludesTriageEvidence(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/href?next=/safe", nil)
	f := findFlow(res, SourceURLQuery, "next", "HTMLAnchorElement.href")
	if f == nil {
		t.Fatalf("no query -> anchor.href flow; findings=%s", summarize(res))
	}
	if f.URL == nil || !f.URL.Resolved || !f.URL.SameOrigin {
		t.Fatalf("missing same-origin URL evidence: %+v", f.URL)
	}
	if f.URL.Scheme != "http" || f.URL.CanaryComponent != "query" {
		t.Errorf("unexpected URL classification: %+v", f.URL)
	}
	if f.Triage == nil || f.Triage.Verdict != DOMTriageLikelyBenign {
		t.Errorf("same-origin query propagation triage = %+v, want likely_benign", f.Triage)
	}
}

func TestDOMJavaScriptHintFeedsConfirmProbe(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/hinted-eval", func(c *DOMScanConfig) {
		c.Mode = DOMModeConfirm
		c.SourceHints = []DOMSourceHint{{
			Kind: SourceURLQuery, Name: "dom_payload",
			Discovered: []string{DOMHintJavaScriptAccess},
		}}
	})
	f := findFlow(res, SourceURLQuery, "dom_payload", "eval")
	if f == nil {
		t.Fatalf("JavaScript-only parameter was not probed; findings=%s", summarize(res))
	}
	if !f.Confirmed || f.Triage == nil || f.Triage.Verdict != DOMTriageConfirmed {
		t.Fatalf("hinted eval flow was not confirmed: %+v", f)
	}
	if f.Source == nil || !reflect.DeepEqual(f.Source.DiscoveredBy, []string{DOMHintJavaScriptAccess}) {
		t.Fatalf("hint provenance missing: %+v", f.Source)
	}
	if res.Summary.HintProbesSent == 0 {
		t.Error("summary did not count source-intelligence probes")
	}
}

func TestDOMFormFieldsHaveUniqueIdentity(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/form-fields", nil)
	f := findFlow(res, SourceFormInput, "body", "innerHTML")
	if f == nil {
		t.Fatalf("named form field -> innerHTML flow missing; findings=%s", summarize(res))
	}
	if findFlow(res, SourceFormInput, "input", "innerHTML") != nil {
		t.Error("form flow fell back to ambiguous generic input identity")
	}
}

func TestDOMSeparatesOriginInspectionFromValidation(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/pm-origin", nil)
	// The listener inspects origin, so we must record that as evidence...
	var checked bool
	for _, f := range res.Findings {
		if f.Type == DOMTypeWebMessage && f.Message != nil && f.Message.OriginChecked {
			checked = true
		}
		// ...but never claim a validation bypass we did not test for.
		if strings.Contains(strings.ToLower(f.Notes), "bypass") {
			t.Errorf("finding claims an origin-validation bypass without a cross-origin test: %+v", f)
		}
	}
	if !checked {
		t.Fatalf("origin inspection not recorded as evidence; findings=%s", summarize(res))
	}
}

func TestDOMRedactsSensitiveSourceValues(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/storage", nil)
	f := findFlow(res, SourceLocalStorage, "", "innerHTML")
	if f == nil {
		t.Fatalf("no local_storage -> innerHTML flow; findings=%s", summarize(res))
	}
	// The preview must be bounded and must only ever contain our injected marker,
	// never an unbounded or real storage value.
	if len([]rune(f.ValuePreview)) > 200 {
		t.Errorf("value preview not bounded: %d runes", len([]rune(f.ValuePreview)))
	}
	if !strings.Contains(f.ValuePreview, "jsmdomc") {
		t.Errorf("preview should show the injected marker, got %q", f.ValuePreview)
	}
}

func TestDOMEnforcesPageAndProbeLimits(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/hub", func(c *DOMScanConfig) {
		c.Crawl = true
		c.MaxDepth = 3
		c.MaxPages = 2
		c.MaxProbes = 20
	})
	if res.Summary.PagesScanned > 2 {
		t.Errorf("page limit exceeded: scanned %d, limit 2", res.Summary.PagesScanned)
	}
	if res.Summary.ProbesSent > 20 {
		t.Errorf("probe limit exceeded: sent %d, limit 20", res.Summary.ProbesSent)
	}
	if res.Summary.ProbesLimit != 20 {
		t.Errorf("summary should report the probe limit, got %d", res.Summary.ProbesLimit)
	}
}

func TestDOMConfirmModeConfirmsExecution(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	res := runDOM(t, srv.URL+"/fragment", func(c *DOMScanConfig) { c.Mode = DOMModeConfirm })
	f := findFlow(res, SourceURLFragment, "", "eval")
	if f == nil {
		t.Fatalf("no fragment -> eval flow; findings=%s", summarize(res))
	}
	if !f.Confirmed {
		t.Fatalf("confirm mode did not confirm execution: %+v", f)
	}
	if f.Confidence != ConfidenceCertain {
		t.Errorf("confirmed flow confidence = %q, want certain", f.Confidence)
	}
}

func TestDOMObserveModeDoesNotInject(t *testing.T) {
	defer domTestSetup(t)()
	srv := vulnServer()
	defer srv.Close()

	// In observe mode the scanner must not inject canaries, so the innerHTML sink
	// is observed (dom_sink) but no controllable flow is asserted.
	res := runDOM(t, srv.URL+"/innerhtml?q=hello", func(c *DOMScanConfig) { c.Mode = DOMModeObserve })
	for _, f := range res.Findings {
		if f.Type == DOMTypeFlow {
			t.Errorf("observe mode must not report canary flows: %+v", f)
		}
	}
	var sawSink bool
	for _, f := range res.Findings {
		if f.Type == DOMTypeSink {
			sawSink = true
		}
	}
	if !sawSink {
		t.Logf("no dom_sink observed (page may not have run the sink under observe); findings=%s", summarize(res))
	}
}

func summarize(res DOMScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%d findings] ", len(res.Findings))
	for _, f := range res.Findings {
		src, sink := "", ""
		if f.Source != nil {
			src = f.Source.Kind + "/" + f.Source.Name
		}
		if f.Sink != nil {
			sink = f.Sink.Name
		}
		fmt.Fprintf(&b, "{%s %s->%s sev=%s conf=%s confirmed=%t frame=%s} ", f.Type, src, sink, f.Severity, f.Confidence, f.Confirmed, f.FrameURL)
	}
	return b.String()
}
