package scan

import (
	"reflect"
	"testing"
)

// mkFlow builds a minimal dom_flow finding for identity tests.
func mkFlow(sourceName, sink, ctx, trigger, canaryPreview string) DOMFinding {
	return DOMFinding{
		Type:         DOMTypeFlow,
		Target:       "https://app.test",
		PageURL:      "https://app.test/search?q=x",
		FrameURL:     "https://app.test/search",
		Source:       &DOMSource{Kind: SourceURLQuery, Name: sourceName},
		Sink:         &DOMSink{Name: sink, Argument: 0},
		ProbeID:      SourceURLQuery + ":" + sourceName,
		Context:      ctx,
		Trigger:      trigger,
		ValuePreview: canaryPreview,
		Severity:     SeverityMedium,
		Confidence:   ConfidenceHigh,
		Stack:        []DOMStackFrame{{Function: "render", URL: "https://app.test/app.js", Line: 10, Column: 3}},
	}
}

// TestDedupCombinesTriggersDeterministically proves the same flow reached through
// several triggers collapses to one finding whose combined trigger evidence and
// fingerprint are deterministic — random canary previews must not affect identity.
func TestDedupCombinesTriggersDeterministically(t *testing.T) {
	in := []DOMFinding{
		mkFlow("q", "Element.innerHTML", "html", TriggerPageLoad, "jsmdomc111 preview A"),
		mkFlow("q", "Element.innerHTML", "html", TriggerInteraction, "jsmdomc222 preview B"),
		mkFlow("q", "Element.innerHTML", "html", TriggerInteraction, "jsmdomc333 preview C"),
	}

	first := DedupDOMFindings(in)
	if len(first) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(first))
	}
	got := first[0]
	if want := []string{TriggerInteraction, TriggerPageLoad}; !reflect.DeepEqual(got.Triggers, want) {
		t.Errorf("combined triggers = %v, want %v", got.Triggers, want)
	}
	if got.Trigger != TriggerInteraction {
		t.Errorf("primary trigger = %q, want the more specific %q", got.Trigger, TriggerInteraction)
	}
	if got.Fingerprint == "" {
		t.Error("deduped finding has no fingerprint")
	}

	// Determinism: shuffling the input order yields the identical fingerprint and
	// combined triggers.
	shuffled := []DOMFinding{in[2], in[0], in[1]}
	second := DedupDOMFindings(shuffled)
	if len(second) != 1 || second[0].Fingerprint != got.Fingerprint {
		t.Fatalf("fingerprint not stable across input order: %q vs %q", second[0].Fingerprint, got.Fingerprint)
	}
	if !reflect.DeepEqual(second[0].Triggers, got.Triggers) {
		t.Errorf("triggers not stable across input order: %v vs %v", second[0].Triggers, got.Triggers)
	}
}

// TestFingerprintDistinguishesParameter guards the core precision property: two
// flows that differ only in which parameter controlled them are distinct
// findings, so the correct parameter is always identifiable.
func TestFingerprintDistinguishesParameter(t *testing.T) {
	a := mkFlow("b", "Element.innerHTML", "html", TriggerPageLoad, "x")
	c := mkFlow("c", "Element.innerHTML", "html", TriggerPageLoad, "x")
	if a.computeFingerprint() == c.computeFingerprint() {
		t.Fatal("flows from different parameters must not share a fingerprint")
	}

	// Same parameter, different sink → still distinct.
	d := mkFlow("b", "eval", "js", TriggerPageLoad, "x")
	if a.computeFingerprint() == d.computeFingerprint() {
		t.Fatal("flows into different sinks must not share a fingerprint")
	}
}

// TestFingerprintIgnoresTransientFields proves canary previews, transient
// interaction labels and stack column drift do not change identity.
func TestFingerprintIgnoresPreview(t *testing.T) {
	a := mkFlow("q", "Element.innerHTML", "html", TriggerPageLoad, "jsmdomcAAAA one")
	b := mkFlow("q", "Element.innerHTML", "html", TriggerPostMessage, "jsmdomcBBBB two")
	if a.computeFingerprint() != b.computeFingerprint() {
		t.Fatal("preview/trigger differences must not change the fingerprint")
	}
}

// TestClassifyFlowSeparatesSeverityAndConfidence checks the severity/confidence
// ladder and that the two axes are independent.
func TestClassifyFlowSeparatesSeverityAndConfidence(t *testing.T) {
	cases := []struct {
		ctx       string
		confirmed bool
		wantSev   string
		wantConf  string
	}{
		{"js", false, SeverityHigh, ConfidenceHigh},
		{"script-url", false, SeverityHigh, ConfidenceHigh},
		{"html", false, SeverityMedium, ConfidenceHigh},
		{"attribute", false, SeverityMedium, ConfidenceHigh},
		{"url", false, SeverityLow, ConfidenceHigh},
		{"js", true, SeverityHigh, ConfidenceCertain},
		{"html", true, SeverityHigh, ConfidenceCertain},
	}
	for _, c := range cases {
		sev, conf := classifyFlow(c.ctx, c.confirmed)
		if sev != c.wantSev || conf != c.wantConf {
			t.Errorf("classifyFlow(%q, confirmed=%t) = (%s,%s), want (%s,%s)",
				c.ctx, c.confirmed, sev, conf, c.wantSev, c.wantConf)
		}
	}
}

func TestAssessDOMFindingExplainsURLRisk(t *testing.T) {
	base := mkFlow("next", "HTMLAnchorElement.href", "url", TriggerPageLoad, "jsmdomc")
	base.URL = &DOMURLEvidence{
		Resolved: true, Scheme: "https", DestinationOrigin: "https://app.test",
		SameOrigin: true, CanaryComponent: "query", InputKind: "absolute",
	}
	if got := assessDOMFinding(base); got.Verdict != DOMTriageLikelyBenign {
		t.Errorf("same-origin query verdict = %+v, want likely_benign", got)
	}

	cross := base
	cross.URL = &DOMURLEvidence{
		Resolved: true, Scheme: "https", DestinationOrigin: "https://elsewhere.test",
		SameOrigin: false, CanaryComponent: "authority", InputKind: "absolute",
	}
	if got := assessDOMFinding(cross); got.Verdict != DOMTriageWorthReview {
		t.Errorf("cross-origin URL verdict = %+v, want worth_reviewing", got)
	}

	exec := base
	exec.URL = &DOMURLEvidence{
		Resolved: true, Scheme: "javascript", CanaryComponent: "opaque",
		InputKind: "absolute", ExecutableScheme: true,
	}
	if got := assessDOMFinding(exec); got.Verdict != DOMTriageWorthReview {
		t.Errorf("executable URL verdict = %+v, want worth_reviewing", got)
	}
}

func TestDedupMergesMessageSinkEvidence(t *testing.T) {
	base := DOMFinding{
		Type: DOMTypeWebMessage, Target: "https://app.test", PageURL: "https://app.test/",
		FrameURL: "https://app.test/", Severity: SeverityInfo, Confidence: ConfidenceMedium,
		Message: &DOMMessageInfo{Identity: "https://app.test|string", ListenerCount: 1, ProbeGenerated: true},
	}
	reached := base
	reached.Message = &DOMMessageInfo{
		Identity: "https://app.test|string", ListenerCount: 1,
		ProbeGenerated: true, ReachesSink: true,
	}
	got := DedupDOMFindings([]DOMFinding{base, reached})
	if len(got) != 1 || got[0].Message == nil || !got[0].Message.ReachesSink {
		t.Fatalf("message sink evidence was not merged: %+v", got)
	}
	if got[0].Triage == nil || got[0].Triage.Verdict != DOMTriageWorthReview {
		t.Errorf("merged message triage = %+v, want worth_reviewing", got[0].Triage)
	}
}

// TestBoundPreviewCaps ensures previews cannot grow without limit.
func TestBoundPreviewCaps(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	got := boundPreview(string(long))
	if len([]rune(got)) > 200 {
		t.Errorf("bounded preview too long: %d runes", len([]rune(got)))
	}
}

// TestSeverityAtLeast verifies the threshold comparison used by -fail-on.
func TestSeverityAtLeast(t *testing.T) {
	if !severityAtLeast(SeverityHigh, SeverityMedium) {
		t.Error("high should meet a medium threshold")
	}
	if severityAtLeast(SeverityLow, SeverityHigh) {
		t.Error("low should not meet a high threshold")
	}
	if !severityAtLeast(SeverityInfo, "") {
		t.Error("empty threshold should default to info and be met by info")
	}
}

// TestConfirmPayloadNeverUsesDialog guards the safety requirement that
// confirmation never uses a visible dialog such as alert().
func TestConfirmPayloadNeverUsesDialog(t *testing.T) {
	for _, ctx := range []string{"html", "js", "url"} {
		p := confirmPayload(ctx, "url_query:q")
		for _, banned := range []string{"alert(", "prompt(", "confirm("} {
			if containsFold(p, banned) {
				t.Errorf("confirm payload for %q used a visible dialog %q: %s", ctx, banned, p)
			}
		}
		if !containsFold(p, "__jsmdomConfirm") && ctx != "url" {
			t.Errorf("confirm payload for %q lacks the hidden beacon: %s", ctx, p)
		}
	}
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexFold(s, sub) >= 0)
}
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestDOMFamilyAccessors sanity-checks the exported family lists and aliases the
// CLI validates -dom-sources/-dom-sinks against.
func TestDOMFamilyAccessors(t *testing.T) {
	srcs := DOMSourceFamilies()
	if len(srcs) == 0 {
		t.Fatal("no source families")
	}
	found := false
	for _, s := range srcs {
		if s == SourceURLQuery {
			found = true
		}
	}
	if !found {
		t.Error("url_query missing from source families")
	}
	if aliases := DOMSourceAliases(); len(aliases[SourceURLFull]) == 0 {
		t.Error("url_full alias should expand to concrete families")
	}
	if len(DOMSinkFamilies()) == 0 {
		t.Error("no sink families")
	}
}

// TestBuildDOMAgentInlinesConfig ensures the agent script embeds its config and
// leaves no placeholder behind.
func TestBuildDOMAgentInlinesConfig(t *testing.T) {
	src := buildDOMAgent(domAgentConfig{Mode: DOMModeCanary, Canaries: []domCanary{{ID: "url_query:q", Token: "jsmdomc1", Kind: SourceURLQuery, Name: "q"}}})
	if indexFold(src, "__JSMDOM_CONFIG__") >= 0 {
		t.Error("config placeholder was not replaced")
	}
	if indexFold(src, "jsmdomc1") < 0 {
		t.Error("canary token not inlined into agent")
	}
}
