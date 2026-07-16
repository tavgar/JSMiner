package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseJSEndpointsWebSocketEventSource verifies WebSocket and EventSource
// endpoints are extracted, including the bare-relative forms the request-call
// heuristic does not cover.
func TestParseJSEndpointsWebSocketEventSource(t *testing.T) {
	data := []byte(`
		const s  = new WebSocket("wss://rt.example.com/socket");
		const es = new EventSource("/events/stream");
		var   w2 = new WebSocket("realtime/feed");
		let   e2 = EventSource("sse/updates");
	`)
	got := map[string]bool{}
	for _, ep := range parseJSEndpoints(data) {
		got[ep.Value] = true
	}
	for _, w := range []string{
		"wss://rt.example.com/socket",
		"/events/stream",
		"realtime/feed",
		"sse/updates",
	} {
		if !got[w] {
			t.Errorf("missing WS/SSE endpoint %q", w)
		}
	}
}

// TestScanReaderExtractsEndpointsFromJSON verifies a JSON body (whose source URL
// has no .js/.json extension) still yields endpoint matches, so a crawl can follow
// the hypermedia links an API response carries.
func TestScanReaderExtractsEndpointsFromJSON(t *testing.T) {
	e := NewExtractor(false, false)
	body := `{"data":[{"id":1}],"_links":{"self":{"href":"/api/orders"},"next":{"href":"/api/orders?page=2"}}}`
	ms, err := e.ScanReaderWithEndpoints("https://api.example.com/api/orders", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range ms {
		if m.Pattern == "endpoint_url" || m.Pattern == "endpoint_path" {
			got[m.Value] = true
		}
	}
	for _, w := range []string{"/api/orders", "/api/orders?page=2"} {
		if !got[w] {
			t.Errorf("hypermedia link %q not extracted from JSON body", w)
		}
	}
}

// TestScanURLCrawlFollowsJSONHypermedia verifies the crawl follows a hypermedia
// "next" link inside a JSON API response to reach a paginated resource that
// nothing in the HTML or JS references, and finds the secret it holds.
func TestScanURLCrawlFollowsJSONHypermedia(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJwYWdlIjoyfQ.jsonHypermediaSigAAAA"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><script>fetch('/api/orders');</script></html>`)
		case r.URL.Path == "/api/orders" && r.URL.RawQuery == "":
			// Page 1: only a hypermedia link points at page 2.
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[{"id":1}],"_links":{"next":{"href":"/api/orders?page=2"}}}`)
		case r.URL.Path == "/api/orders" && r.URL.RawQuery == "page=2":
			// Page 2: holds the secret, reachable only via the JSON link.
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[{"id":2,"token":"`+secret+`"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	opts := CrawlOptions{MaxDepth: 3, MaxPages: 20, SameScopeOnly: true}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Value == secret {
			return
		}
	}
	t.Fatal("secret behind the JSON hypermedia link was not reached")
}
