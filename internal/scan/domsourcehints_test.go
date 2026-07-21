package scan

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoverDOMSourceHintsFromJavaScript(t *testing.T) {
	js := []byte(`
const qp = new URLSearchParams(location.search);
qp.get("template");
router.query.return_to;
fetch("/api/search?language=" + lang, {method:"POST", body: JSON.stringify({html: value, user_id: id})});
localStorage.getItem("draft_html");
sessionStorage["return_path"];
Cookies.get("session_hint");
`)
	hints := discoverDOMSourceHints(js)
	has := func(kind, name, provenance string) bool {
		for _, hint := range hints {
			if hint.Kind == kind && hint.Name == name {
				for _, got := range hint.Discovered {
					if got == provenance {
						return true
					}
				}
			}
		}
		return false
	}
	for _, want := range []struct{ kind, name, provenance string }{
		{SourceURLQuery, "template", DOMHintJavaScriptAccess},
		{SourceURLQuery, "return_to", DOMHintJavaScriptAccess},
		{SourceURLQuery, "language", DOMHintJavaScriptURL},
		{SourceURLQuery, "html", DOMHintJavaScriptRequest},
		{SourceURLQuery, "user_id", DOMHintJavaScriptRequest},
		{SourceLocalStorage, "draft_html", DOMHintJavaScriptAccess},
		{SourceSessionStorage, "return_path", DOMHintJavaScriptAccess},
		{SourceCookie, "session_hint", DOMHintJavaScriptAccess},
	} {
		if !has(want.kind, want.name, want.provenance) {
			t.Errorf("missing hint %s[%s] via %s: %+v", want.kind, want.name, want.provenance, hints)
		}
	}
}

func TestExtractorCollectsDOMHintsOnlyWhenEnabled(t *testing.T) {
	e := NewExtractor(false, false)
	js := `const p=new URLSearchParams(location.search); p.get("dom_only");`
	if _, err := e.ScanReaderWithEndpoints("app.js", strings.NewReader(js)); err != nil {
		t.Fatal(err)
	}
	if got := e.TakeDOMSourceHints(); len(got) != 0 {
		t.Fatalf("disabled collector returned hints: %+v", got)
	}
	e.SetCollectDOMSourceHints(true)
	if _, err := e.ScanReaderWithEndpoints("app.js", strings.NewReader(js)); err != nil {
		t.Fatal(err)
	}
	got := e.TakeDOMSourceHints()
	if len(got) != 1 || got[0].Kind != SourceURLQuery || got[0].Name != "dom_only" {
		t.Fatalf("collector hints = %+v", got)
	}
}

func TestPassiveCandidateKeepsNamesButDropsValues(t *testing.T) {
	seed, _ := url.Parse("https://app.test/")
	live, names, ok := passivePathCandidateDetails(seed, "https://app.test/old/search?q=secret&lang=en#private")
	if !ok {
		t.Fatal("passive candidate rejected")
	}
	if live != "https://app.test/old/search" {
		t.Fatalf("live URL retained historical data: %q", live)
	}
	if want := []string{"lang", "q"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("passive names = %v, want %v", names, want)
	}
}

func TestBuildCanariesUsesScopedSourceHints(t *testing.T) {
	s := &domScanner{cfg: DOMScanConfig{
		Sources: map[string]bool{SourceURLQuery: true}, MaxSourceHintsPerPage: 10,
		SourceHints: []DOMSourceHint{
			{Kind: SourceURLQuery, Name: "template", ScopeHost: "app.test", Discovered: []string{DOMHintJavaScriptAccess}},
			{Kind: SourceURLQuery, Name: "foreign", ScopeHost: "other.test", Discovered: []string{DOMHintJavaScriptAccess}},
		},
	}}
	canaries, injected, _ := s.buildCanaries("https://app.test/view", -1)
	parsed, err := url.Parse(injected)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("template") == "" || parsed.Query().Get("foreign") != "" {
		t.Fatalf("scoped injected query = %s", parsed.RawQuery)
	}
	var found bool
	for _, canary := range canaries {
		if canary.Name == "template" && reflect.DeepEqual(canary.DiscoveredBy, []string{DOMHintJavaScriptAccess}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("hint provenance missing from canaries: %+v", canaries)
	}
}
