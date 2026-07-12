package scan

import (
	"strings"
	"testing"
)

func TestParseJSEndpoints(t *testing.T) {
	js := `const a = "https://api.example.com/v1";
    fetch('/v1/test');
    fetch("./local/api");
    fetch('../parent/api');
    fetch("//cdn.example.com/lib.js");`
	eps := parseJSEndpoints([]byte(js))
	if len(eps) != 5 {
		t.Fatalf("expected 5 endpoints, got %d", len(eps))
	}
	expected := map[string]bool{
		"https://api.example.com/v1": true,
		"/v1/test":                   false,
		"./local/api":                false,
		"../parent/api":              false,
		"//cdn.example.com/lib.js":   true,
	}
	for _, e := range eps {
		v, ok := expected[e.Value]
		if !ok {
			t.Fatalf("unexpected endpoint %s", e.Value)
		}
		if v != e.IsURL {
			t.Fatalf("endpoint %s classification mismatch", e.Value)
		}
		delete(expected, e.Value)
	}
	if len(expected) != 0 {
		t.Fatalf("missing endpoints: %v", expected)
	}
}

func TestScanReaderWithEndpoints(t *testing.T) {
	js := `fetch("https://ex.com/api"); axios.get('/v2/data');`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	var urls, paths []string
	for _, m := range matches {
		switch m.Pattern {
		case "endpoint_url":
			urls = append(urls, m.Value)
		case "endpoint_path":
			paths = append(paths, m.Value)
		}
	}
	if len(urls) != 1 || len(paths) != 1 {
		t.Fatalf("expected 1 url and 1 path, got %d and %d", len(urls), len(paths))
	}
}

func TestScanReaderWithEndpointsNonJS(t *testing.T) {
	js := `fetch("/should/ignore")`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if strings.HasPrefix(m.Pattern, "endpoint_") {
			t.Fatalf("did not expect endpoint match for non-js file")
		}
	}
}

func TestScanReaderFiltersInvalidEndpoints(t *testing.T) {
	js := `fetch("http://a"); fetch('/./'); fetch('//'); fetch('/$'); fetch('https://valid.com/api');`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderWithEndpoints("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 valid endpoint, got %d", len(matches))
	}
	if matches[0].Value != "https://valid.com/api" {
		t.Fatalf("unexpected endpoint %s", matches[0].Value)
	}
}

// TestParseJSEndpointsExtended covers the endpoint forms added for broader,
// still-precise recall: WebSocket URLs, template-literal bases, and bare
// relative request paths captured only in request-call context.
func TestParseJSEndpointsExtended(t *testing.T) {
	js := "fetch(`${API}/api/user/${id}/posts`);\n" + // template -> static base
		"fetch('api/bare/items');\n" + // bare relative in fetch()
		"axios.post('v3/orders/create', body);\n" + // bare relative in axios
		"new WebSocket('wss://sock.example.com/live');\n" +
		"new WebSocket('ws://sock.example.com/live2');\n" +
		"const ct = 'application/json';\n" + // trap: not a request call
		"const ar = '16/9';\n" + // trap: not a request call
		"cache.get('plain-key');\n" // trap: .get() but no path segment

	got := map[string]bool{}
	for _, e := range parseJSEndpoints([]byte(js)) {
		got[e.Value] = e.IsURL
	}
	want := map[string]bool{
		"/api/user/":                  false, // template trimmed to crawlable base
		"api/bare/items":              false,
		"v3/orders/create":            false,
		"wss://sock.example.com/live": true,
		"ws://sock.example.com/live2": true,
	}
	for v, isURL := range want {
		gu, ok := got[v]
		if !ok {
			t.Errorf("missing endpoint %q", v)
			continue
		}
		if gu != isURL {
			t.Errorf("endpoint %q IsURL=%v, want %v", v, gu, isURL)
		}
	}
	for _, bad := range []string{"application/json", "16/9", "plain-key"} {
		if _, ok := got[bad]; ok {
			t.Errorf("trap value %q was wrongly extracted as an endpoint", bad)
		}
	}
}

// TestValidEndpointPathBareRelative verifies that multi-segment bare relative
// paths are accepted while lone tokens and dotted non-paths are not.
func TestValidEndpointPathBareRelative(t *testing.T) {
	cases := map[string]bool{
		"api/users":        true,
		"v3/orders/create": true,
		"/api/rooted":      true,
		"plain":            false, // single token, no segment
		"16/9":             true,  // shape is a valid path; precision comes from extraction context
		"a/b":              true,
	}
	for val, want := range cases {
		if got := validEndpointPath(val); got != want {
			t.Errorf("validEndpointPath(%q) = %v, want %v", val, got, want)
		}
	}
}
