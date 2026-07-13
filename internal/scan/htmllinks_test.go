package scan

import "testing"

func TestExtractHTMLLinkMatches(t *testing.T) {
	page := "https://site.test/dir/page"
	html := []byte(`<!doctype html><html><head>
<link rel="stylesheet" href="/css/app.css">
<base>
</head><body>
<a href="/api/v1/users">rooted</a>
<a href="products/42">bare relative</a>
<a href="../up/one">dot-relative</a>
<a href="https://other.test/ext">absolute external</a>
<a href="#section">fragment only</a>
<a href="javascript:void(0)">js</a>
<a href="mailto:a@b.test">mail</a>
<a href="tel:+1555">tel</a>
<form action="/submit/here" method="post"></form>
<img src="/img/logo.png?v=2">
<iframe src="frames/inner.html"></iframe>
<a href="/search?q=a&amp;b=2">entity query</a>
</body></html>`)

	got := map[string]bool{}
	for _, m := range extractHTMLLinkMatches(html, page) {
		if m.Pattern != "endpoint_url" {
			t.Errorf("pattern = %q, want endpoint_url", m.Pattern)
		}
		got[m.Value] = true
	}

	wantPresent := []string{
		"https://site.test/css/app.css",
		"https://site.test/api/v1/users",
		"https://site.test/dir/products/42", // bare relative resolved against page dir
		"https://site.test/up/one",          // ../ resolved
		"https://other.test/ext",            // external kept (scope filtering happens later)
		"https://site.test/submit/here",     // form action
		"https://site.test/img/logo.png?v=2",
		"https://site.test/dir/frames/inner.html",
		"https://site.test/search?q=a&b=2", // &amp; decoded
	}
	for _, w := range wantPresent {
		if !got[w] {
			t.Errorf("missing expected link %q", w)
		}
	}

	// Non-navigational schemes and fragment-only links must not appear.
	for v := range got {
		for _, bad := range []string{"javascript:", "mailto:", "tel:", "#section"} {
			if v == bad || (len(v) >= len(bad) && v[:min(len(bad), len(v))] == bad) {
				t.Errorf("unexpected non-nav link surfaced: %q", v)
			}
		}
	}
	if got["https://site.test/dir/page#section"] || len(got) == 0 {
		t.Errorf("fragment-only link should be dropped; got set %v", got)
	}
}

// TestExtractHTMLLinkMatchesDedup verifies repeated links collapse to one match.
func TestExtractHTMLLinkMatchesDedup(t *testing.T) {
	html := []byte(`<a href="/x">1</a><a href="/x#a">2</a><a href="/x">3</a>`)
	n := len(extractHTMLLinkMatches(html, "https://s.test/"))
	if n != 1 {
		t.Fatalf("expected 1 deduped link, got %d", n)
	}
}
