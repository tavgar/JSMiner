package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExtractLinkHeaderMatches checks that navigable rels are followed, that a
// comma inside a target URL does not fracture an entry, that asset/hint rels and
// self are skipped, and that relative targets resolve against the page.
func TestExtractLinkHeaderMatches(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://api.example.com/orders?ids=1,2,3&page=2>; rel="next", </orders?page=1>; rel="prev"`)
	h.Add("Link", `<https://cdn.example.com/app.css>; rel="stylesheet"`)
	h.Add("Link", `<https://api.example.com/orders?page=2>; rel="self"`)
	h.Add("Link", `<https://api.example.com/schema>; rel="describedby"`)

	got := map[string]bool{}
	for _, m := range extractLinkHeaderMatches(h, "https://api.example.com/orders") {
		if m.Pattern != "endpoint_url" {
			t.Errorf("unexpected pattern %q", m.Pattern)
		}
		got[m.Value] = true
	}

	want := []string{
		"https://api.example.com/orders?ids=1,2,3&page=2", // next, comma in query kept intact
		"https://api.example.com/orders?page=1",           // prev, relative resolved
		"https://api.example.com/schema",                  // describedby
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing navigable Link target %q", w)
		}
	}
	for _, notWant := range []string{
		"https://cdn.example.com/app.css",       // stylesheet: asset rel
		"https://api.example.com/orders?page=2", // self: current resource
	} {
		if got[notWant] {
			t.Errorf("followed non-navigational Link target %q", notWant)
		}
	}
}

// TestScanURLCrawlFollowsLinkHeader verifies the crawl follows a `Link:
// rel="next"` response header to reach a paginated API page that nothing in the
// body references, and finds the secret it holds.
func TestScanURLCrawlFollowsLinkHeader(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJwYWdlIjoyfQ.linkHeaderPaginationAAA"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><script>fetch('/api/items');</script></html>`)
		case r.URL.Path == "/api/items" && r.URL.RawQuery == "":
			// Page 1: the only pointer to page 2 is the Link header.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<`+r.Host+`>`) // ignored: no scheme
			w.Header().Set("Link", `</api/items?page=2>; rel="next"`)
			io.WriteString(w, `{"data":[{"id":1}]}`)
		case r.URL.Path == "/api/items" && r.URL.RawQuery == "page=2":
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
	t.Fatal("secret behind the Link: rel=next header was not reached")
}
