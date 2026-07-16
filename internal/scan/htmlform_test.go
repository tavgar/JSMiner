package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestExtractHTMLFormMatches checks that a POST form yields a post_url match with
// its field names as form-encoded params, that the action resolves against the
// page, that a self-posting form falls back to the page URL, and that GET forms are
// ignored (their action is harvested as a navigable link elsewhere).
func TestExtractHTMLFormMatches(t *testing.T) {
	page := "https://example.com/account/settings"
	data := []byte(`
		<form method="POST" action="/account/update">
			<input type="text" name="display_name">
			<input type="hidden" name="csrf_token" value="x">
			<select name="timezone"><option>UTC</option></select>
			<textarea name="bio"></textarea>
			<button type="submit">Save</button>
		</form>
		<form method="post">
			<input name="q">
		</form>
		<form method="get" action="/search">
			<input name="query">
		</form>
	`)

	got := map[string]string{} // action -> params
	for _, m := range extractHTMLFormMatches(data, page) {
		if m.Pattern != "post_url" {
			t.Errorf("unexpected pattern %q", m.Pattern)
		}
		got[m.Value] = m.Params
	}

	// POST form with an explicit action, resolved against the page origin.
	params, ok := got["https://example.com/account/update"]
	if !ok {
		t.Fatalf("POST form action not emitted; got %v", got)
	}
	for _, want := range []string{"display_name=", "csrf_token=", "timezone=", "bio="} {
		if !strings.Contains(params, want) {
			t.Errorf("params %q missing field %q", params, want)
		}
	}

	// Self-posting POST form (no action) falls back to the page URL.
	if _, ok := got[page]; !ok {
		t.Errorf("self-posting form not attributed to the page URL; got %v", got)
	}

	// GET form must not be emitted as a POST target.
	if _, ok := got["https://example.com/search"]; ok {
		t.Errorf("GET form leaked into POST form matches")
	}
}

// TestCrawlReplaysHTMLFormParams verifies the crawl lifts a POST form's field
// names out of a page's markup and feeds them into cross-level parameter replay:
// the harvested fields are submitted, as a POST body, against a directory level the
// crawl saw — so the server receives a POST carrying exactly those field names.
// Without form harvesting the crawl would only ever replay parameters mined from
// JavaScript, and this form (whose fields appear in no script) would be invisible.
func TestCrawlReplaysHTMLFormParams(t *testing.T) {
	ResetThrottle()

	var sawFormPost int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Any replayed POST that carries the harvested form fields proves the form's
		// parameters reached the replay engine.
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.Form.Has("feed_url") && r.Form.Has("token") {
				atomic.StoreInt32(&sawFormPost, 1)
			}
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body>
				<a href="/app/profile">profile</a>
				<a href="/app/import">import</a>
			</body></html>`)
		case "/app/profile":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body>
				<form method="post" action="/app/import">
					<input name="feed_url">
					<input name="token">
				</form>
			</body></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body>ok</body></html>`)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	opts := DefaultCrawlOptions()
	opts.Concurrency = 1
	opts.DiscoverWellKnown = false // keep the test's request graph tight
	if _, err := e.ScanURLCrawl(ts.URL, false, false, false, opts); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&sawFormPost) == 0 {
		t.Fatal("harvested HTML form parameters were never replayed as a POST body")
	}
}
