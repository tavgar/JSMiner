package scan

import (
	"context"
	"strings"
	"testing"
)

func TestScanDOMSkipsBrowserWhenNoURLTargets(t *testing.T) {
	e := NewExtractor(false, false)
	res, err := e.ScanDOM(context.Background(), []string{"local.js", "mailto:test@example.com"}, DefaultDOMScanConfig())
	if err != nil {
		t.Fatalf("invalid target set should be reported, not start a browser: %v", err)
	}
	if res.Summary.PagesScanned != 0 || len(res.Summary.Errors) != 2 {
		t.Fatalf("unexpected summary: %+v", res.Summary)
	}
}

func TestConfirmFlowsIsScopedToPageAndContext(t *testing.T) {
	s := &domScanner{findings: []DOMFinding{
		{Type: DOMTypeFlow, PageURL: "https://app.test/one", ProbeID: "url_query:q", Context: "html"},
		{Type: DOMTypeFlow, PageURL: "https://app.test/two", ProbeID: "url_query:q", Context: "html"},
		{Type: DOMTypeFlow, PageURL: "https://app.test/one", ProbeID: "url_query:q", Context: "js"},
	}}
	s.confirmFlows("https://app.test/one", "url_query:q", "html")

	if !s.findings[0].Confirmed {
		t.Fatal("matching page/context flow was not confirmed")
	}
	if s.findings[1].Confirmed {
		t.Fatal("confirmation leaked to another page with the same source id")
	}
	if s.findings[2].Confirmed {
		t.Fatal("confirmation leaked to another sink context")
	}
}

func TestHTMLConfirmPayloadDoesNotIssueTargetRequest(t *testing.T) {
	payload := confirmPayload("html", "url_query:q|html")
	if !strings.Contains(payload, `src="data:image/png;base64,!"`) {
		t.Fatalf("HTML confirmation should use a local data URI: %s", payload)
	}
	if !strings.Contains(payload, "jsmdomk") {
		t.Fatalf("HTML confirmation lost its attribution marker: %s", payload)
	}
}

// TestSuppressUninterestingMessages keeps only web_message findings that carry a
// security signal — a listener, a sink hit or a cross-origin leak — and drops the
// bare chatter (a message with no receiver and no effect). Non-message findings
// are never touched.
func TestSuppressUninterestingMessages(t *testing.T) {
	findings := []DOMFinding{
		{Type: DOMTypeWebMessage, Message: &DOMMessageInfo{ListenerCount: 0}},               // chatter -> drop
		{Type: DOMTypeWebMessage, Message: &DOMMessageInfo{ProbeGenerated: true}},           // probe echo, no listener -> drop
		{Type: DOMTypeWebMessage, Message: &DOMMessageInfo{ListenerCount: 1}},               // real receiver -> keep
		{Type: DOMTypeWebMessage, Message: &DOMMessageInfo{ReachesSink: true}},              // sink hit -> keep
		{Type: DOMTypeWebMessage, Message: &DOMMessageInfo{SentToOrigin: "https://evil.x"}}, // leak -> keep
		{Type: DOMTypeFlow, Sink: &DOMSink{Name: "eval"}},                                   // not a message -> keep
	}
	kept, suppressed := suppressUninterestingMessages(findings)
	if suppressed != 2 {
		t.Fatalf("suppressed = %d, want 2", suppressed)
	}
	if len(kept) != 4 {
		t.Fatalf("kept = %d, want 4: %+v", len(kept), kept)
	}
	for _, f := range kept {
		if f.Type == DOMTypeWebMessage && !messageIsInteresting(f.Message) {
			t.Errorf("kept an uninteresting message finding: %+v", f.Message)
		}
	}
}

// TestMessageDedupCollapsesPerListener verifies that two distinct incoming
// messages (different origin/shape identities) handled by the *same* listener
// collapse to one finding about that receiver, so a busy page's message traffic
// no longer produces one finding per message. The merged record keeps the
// stronger reaches-sink evidence.
func TestMessageDedupCollapsesPerListener(t *testing.T) {
	loc := []DOMStackFrame{{URL: "https://app.test/app.js", Line: 10, Column: 5}}
	base := DOMFinding{Type: DOMTypeWebMessage, Target: "https://app.test", PageURL: "https://app.test/"}
	a := base
	a.Message = &DOMMessageInfo{Identity: "https://ads.example|{cmd}", ListenerCount: 1, ListenerLocations: loc}
	b := base
	b.Message = &DOMMessageInfo{Identity: "https://cdn.example|{data}", ListenerCount: 1, ListenerLocations: loc, ReachesSink: true}

	out := DedupDOMFindings([]DOMFinding{a, b})
	if len(out) != 1 {
		t.Fatalf("messages sharing one listener should collapse to 1 finding, got %d", len(out))
	}
	if out[0].Message == nil || !out[0].Message.ReachesSink {
		t.Errorf("merged listener finding lost its reaches_sink evidence: %+v", out[0].Message)
	}
}

// TestMessageDedupKeepsDistinctListenersSeparate ensures messages handled by
// different listeners are not merged, so two genuinely different receivers stay
// two findings.
func TestMessageDedupKeepsDistinctListenersSeparate(t *testing.T) {
	base := DOMFinding{Type: DOMTypeWebMessage, Target: "https://app.test", PageURL: "https://app.test/"}
	a := base
	a.Message = &DOMMessageInfo{Identity: "x|y", ListenerCount: 1, ListenerLocations: []DOMStackFrame{{URL: "https://app.test/a.js", Line: 1}}}
	b := base
	b.Message = &DOMMessageInfo{Identity: "x|y", ListenerCount: 1, ListenerLocations: []DOMStackFrame{{URL: "https://app.test/b.js", Line: 2}}}

	if out := DedupDOMFindings([]DOMFinding{a, b}); len(out) != 2 {
		t.Fatalf("distinct listeners should stay separate, got %d findings", len(out))
	}
}
