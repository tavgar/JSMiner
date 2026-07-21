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
