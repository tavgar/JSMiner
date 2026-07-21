package scan

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// hostOfURL returns the hostname component of a raw URL for scoping a hint.
func hostOfURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}

func runReflection(t *testing.T, target string, cfg ReflectionScanConfig) ReflectionScanResult {
	t.Helper()
	e := NewExtractor(false, false)
	res, err := e.ScanReflections(context.Background(), []string{target}, cfg)
	if err != nil {
		t.Fatalf("ScanReflections: %v", err)
	}
	return res
}

func findReflection(res ReflectionScanResult, param string) *ReflectionFinding {
	for i := range res.Findings {
		if res.Findings[i].Parameter == param {
			return &res.Findings[i]
		}
	}
	return nil
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// TestScanReflectionsHTMLTextUnfiltered detects a raw reflection in HTML body
// text with all breakout characters surviving, rated medium.
func TestScanReflectionsHTMLTextUnfiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>You searched for: " + r.URL.Query().Get("q") + " done</body></html>"))
	}))
	defer srv.Close()

	res := runReflection(t, srv.URL+"/search?q=test", DefaultReflectionScanConfig())
	f := findReflection(res, "q")
	if f == nil {
		t.Fatalf("expected a reflection for q, got %d findings", len(res.Findings))
	}
	if f.Context != ReflectionContextHTMLText {
		t.Errorf("context = %q, want %q", f.Context, ReflectionContextHTMLText)
	}
	for _, c := range []string{"<", ">", "\"", "'", "`"} {
		if !hasLabel(f.Unfiltered, c) {
			t.Errorf("expected %q in unfiltered set %v", c, f.Unfiltered)
		}
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.Triage == nil || f.Triage.Verdict != DOMTriageWorthReview {
		t.Errorf("triage = %+v, want worth_reviewing", f.Triage)
	}
	if f.Method != "GET" {
		t.Errorf("method = %q, want GET", f.Method)
	}
}

// TestScanReflectionsEncodedIsBenign keeps an HTML-encoded reflection low
// severity: the value is echoed but its angle brackets are neutralised.
func TestScanReflectionsEncodedIsBenign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>q=" + html.EscapeString(r.URL.Query().Get("q")) + "</body></html>"))
	}))
	defer srv.Close()

	res := runReflection(t, srv.URL+"/?q=test", DefaultReflectionScanConfig())
	f := findReflection(res, "q")
	if f == nil {
		t.Fatalf("expected a reflection for q, got %d findings", len(res.Findings))
	}
	if hasLabel(f.Unfiltered, "<") || hasLabel(f.Unfiltered, ">") {
		t.Errorf("angle brackets should be encoded, unfiltered = %v", f.Unfiltered)
	}
	if f.Severity != SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
	if f.Triage == nil || f.Triage.Verdict != DOMTriageLikelyBenign {
		t.Errorf("triage = %+v, want likely_benign", f.Triage)
	}
}

// TestScanReflectionsAttributeContext classifies a reflection inside a quoted
// attribute value and flags the surviving quote.
func TestScanReflectionsAttributeContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><input name="x" value="` + r.URL.Query().Get("x") + `"></body></html>`))
	}))
	defer srv.Close()

	res := runReflection(t, srv.URL+"/?x=y", DefaultReflectionScanConfig())
	f := findReflection(res, "x")
	if f == nil {
		t.Fatalf("expected a reflection for x, got %d findings", len(res.Findings))
	}
	if f.Context != ReflectionContextHTMLAttr {
		t.Errorf("context = %q, want %q", f.Context, ReflectionContextHTMLAttr)
	}
	if !hasLabel(f.Unfiltered, "\"") {
		t.Errorf("expected double quote in unfiltered set %v", f.Unfiltered)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
}

// TestScanReflectionsScriptContext classifies a reflection inside a <script>
// block and flags surviving string-breakout characters.
func TestScanReflectionsScriptContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script>var x = "` + r.URL.Query().Get("s") + `";</script></head></html>`))
	}))
	defer srv.Close()

	res := runReflection(t, srv.URL+"/?s=1", DefaultReflectionScanConfig())
	f := findReflection(res, "s")
	if f == nil {
		t.Fatalf("expected a reflection for s, got %d findings", len(res.Findings))
	}
	if f.Context != ReflectionContextScript {
		t.Errorf("context = %q, want %q", f.Context, ReflectionContextScript)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
}

// TestScanReflectionsNoReflection reports nothing when the parameter is not
// echoed anywhere in the response.
func TestScanReflectionsNoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>static content</body></html>"))
	}))
	defer srv.Close()

	res := runReflection(t, srv.URL+"/?q=test", DefaultReflectionScanConfig())
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Summary.URLsScanned != 1 {
		t.Errorf("URLsScanned = %d, want 1", res.Summary.URLsScanned)
	}
}

// TestScanReflectionsUsesParamHints tests a parameter name that appears nowhere
// on the URL but was mined for the DOM scan.
func TestScanReflectionsUsesParamHints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>redirect=" + r.URL.Query().Get("next") + "</body></html>"))
	}))
	defer srv.Close()

	cfg := DefaultReflectionScanConfig()
	cfg.ParamHints = []DOMSourceHint{{
		Kind: SourceURLQuery, Name: "next", ScopeHost: hostOfURL(t, srv.URL),
		Discovered: []string{DOMHintJavaScriptAccess},
	}}
	res := runReflection(t, srv.URL+"/", cfg)
	f := findReflection(res, "next")
	if f == nil {
		t.Fatalf("expected a reflection for hinted param next, got %d findings", len(res.Findings))
	}
	if !hasLabel(f.DiscoveredBy, DOMHintJavaScriptAccess) {
		t.Errorf("discovered_by = %v, want it to include %q", f.DiscoveredBy, DOMHintJavaScriptAccess)
	}
}

// TestScanReflectionsHintScopedToHost keeps a hint from another host from being
// injected against an unrelated target.
func TestScanReflectionsHintScopedToHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>next=" + r.URL.Query().Get("next") + "</body></html>"))
	}))
	defer srv.Close()

	cfg := DefaultReflectionScanConfig()
	cfg.ParamHints = []DOMSourceHint{{
		Kind: SourceURLQuery, Name: "next", ScopeHost: "unrelated.example",
		Discovered: []string{DOMHintJavaScriptAccess},
	}}
	res := runReflection(t, srv.URL+"/", cfg)
	if len(res.Findings) != 0 {
		t.Fatalf("out-of-scope hint should not be tested, got %d findings", len(res.Findings))
	}
}

// TestScanReflectionsProbeBudget bounds the number of HTTP requests sent.
func TestScanReflectionsProbeBudget(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	cfg := DefaultReflectionScanConfig()
	cfg.MaxProbes = 1
	// Force several batches by capping params-per-batch is internal; instead give a
	// wide param set so more than one request would otherwise be sent.
	hints := make([]DOMSourceHint, 0, 60)
	for i := 0; i < 60; i++ {
		hints = append(hints, DOMSourceHint{Kind: SourceURLQuery, Name: "p" + string(rune('a'+i%26)) + string(rune('a'+i/26)), ScopeHost: hostOfURL(t, srv.URL)})
	}
	cfg.ParamHints = hints
	res := runReflection(t, srv.URL+"/", cfg)
	if res.Summary.ProbesSent > 1 {
		t.Errorf("ProbesSent = %d, want <= 1 (budget)", res.Summary.ProbesSent)
	}
	if hits > 1 {
		t.Errorf("server hit %d times, want <= 1", hits)
	}
	if !res.Summary.Partial {
		t.Error("summary should be marked partial when the probe budget is exhausted")
	}
}

// TestClassifyReflectionContext exercises the structural context classifier
// directly on crafted bodies.
func TestClassifyReflectionContext(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"text", "<html><body>hello MARK there</body>", ReflectionContextHTMLText},
		{"attribute", `<input value="MARK">`, ReflectionContextHTMLAttr},
		{"script", "<script>var a=MARK;</script>", ReflectionContextScript},
		{"comment", "<!-- MARK -->", ReflectionContextHTMLComment},
		{"closed-tag-is-text", "<div class=\"x\">MARK</div>", ReflectionContextHTMLText},
		{"after-script-close", "<script>x</script>MARK", ReflectionContextHTMLText},
	}
	for _, c := range cases {
		lowered := []byte(strings.ToLower(c.body))
		idx := strings.Index(c.body, "MARK")
		if idx < 0 {
			t.Fatalf("%s: MARK not present in body", c.name)
		}
		if got := classifyReflectionContext(lowered, idx); got != c.want {
			t.Errorf("%s: context = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestReflectionRoutesDedup collapses value-only variants of one route and keeps
// distinct parameter-name sets separate.
func TestReflectionRoutesDedup(t *testing.T) {
	in := []string{
		"https://x.test/search?q=a",
		"https://x.test/search?q=b", // same route (same param set) -> collapses
		"https://x.test/search?q=a&sort=1",
		"not a url",
		"ftp://x.test/skip",
	}
	got := reflectionRoutes(in, 0)
	if len(got) != 2 {
		t.Fatalf("routes = %v, want 2 distinct routes", got)
	}
}

// TestReflectionFingerprintDedup collapses two observations of the same
// route/param/context into one finding, keeping the stronger severity.
func TestReflectionFingerprintDedup(t *testing.T) {
	base := ReflectionFinding{
		Type: ReflectionType, Target: "https://x.test", PageURL: "https://x.test/s?q=",
		Parameter: "q", Context: ReflectionContextHTMLText,
	}
	low := base
	low.Severity, low.Confidence = SeverityLow, ConfidenceMedium
	high := base
	high.Severity, high.Confidence = SeverityMedium, ConfidenceHigh
	high.Unfiltered = []string{"<", ">"}
	out := DedupReflectionFindings([]ReflectionFinding{low, high})
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(out))
	}
	if out[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want the stronger medium", out[0].Severity)
	}
}
