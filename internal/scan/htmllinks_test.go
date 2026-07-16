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

// TestExtractHTMLLinkSrcsetAndCSS verifies srcset candidate URLs (on <img> and
// <source>) and CSS url() references (in <style> blocks and inline style) are
// surfaced — occasionally a config/data path hides there — while descriptors and
// data: URIs are not.
func TestExtractHTMLLinkSrcsetAndCSS(t *testing.T) {
	page := "https://site.test/dir/page"
	html := []byte(`<html><head><style>
  .hero { background: url("/assets/bg.webp"); }
  .cfg  { --data: url(/config/app.json); }
  .b64  { background: url("data:image/png;base64,AAAA"); }
</style></head><body>
<img srcset="/img/small.jpg 480w, /img/large.jpg 800w" src="/img/fallback.jpg">
<picture><source srcset="/img/hero.avif 1x, /img/hero@2x.avif 2x"></picture>
<div style="background-image:url('/theme/skin.css')"></div>
</body></html>`)

	got := map[string]bool{}
	for _, m := range extractHTMLLinkMatches(html, page) {
		got[m.Value] = true
	}

	for _, w := range []string{
		"https://site.test/assets/bg.webp",   // css url() double-quoted
		"https://site.test/config/app.json",  // css url() bare
		"https://site.test/theme/skin.css",   // inline style url() single-quoted
		"https://site.test/img/small.jpg",    // srcset candidate 1
		"https://site.test/img/large.jpg",    // srcset candidate 2
		"https://site.test/img/fallback.jpg", // plain src still works
		"https://site.test/img/hero.avif",    // <source> srcset candidate 1
		"https://site.test/img/hero@2x.avif", // <source> srcset candidate 2
	} {
		if !got[w] {
			t.Errorf("missing expected link %q", w)
		}
	}
	// The data: URI and the width/density descriptors must not leak as endpoints.
	for v := range got {
		if len(v) >= 5 && v[:5] == "data:" {
			t.Errorf("data: URI surfaced as endpoint: %q", v)
		}
		for _, desc := range []string{"480w", "800w", "1x", "2x"} {
			if v == desc {
				t.Errorf("srcset descriptor surfaced as endpoint: %q", v)
			}
		}
	}
}

// TestExtractHTMLLinkTemplatePlaceholders verifies unresolved template
// expressions in href/src are not emitted as garbage endpoints.
func TestExtractHTMLLinkTemplatePlaceholders(t *testing.T) {
	html := []byte(`
<a href="${base}/api">a</a>
<a href="/users/{{id}}">b</a>
<a href="/p/<%=n%>">c</a>
<a href="/e/#{path}">d</a>
<a href="/real/page">e</a>`)
	got := []string{}
	for _, m := range extractHTMLLinkMatches(html, "https://s.test/") {
		got = append(got, m.Value)
	}
	if len(got) != 1 || got[0] != "https://s.test/real/page" {
		t.Fatalf("template placeholders should be dropped, only /real/page kept; got %v", got)
	}
}

// TestExtractHTMLLinkMetaRefresh verifies a meta-refresh redirect target is found.
func TestExtractHTMLLinkMetaRefresh(t *testing.T) {
	cases := []string{
		`<meta http-equiv="refresh" content="0; url=/landing">`,
		`<meta content="5;URL=/landing" http-equiv=refresh>`,
		`<META HTTP-EQUIV="REFRESH" CONTENT="0;url=/landing">`,
	}
	for _, html := range cases {
		got := extractHTMLLinkMatches([]byte(html), "https://s.test/dir/page")
		found := false
		for _, m := range got {
			if m.Value == "https://s.test/landing" {
				found = true
			}
		}
		if !found {
			t.Errorf("meta refresh target not found in %q -> %v", html, got)
		}
	}
	// A non-refresh meta must not yield a link.
	if got := extractHTMLLinkMatches([]byte(`<meta name="x" content="url=/nope">`), "https://s.test/"); len(got) != 0 {
		t.Errorf("non-refresh meta should yield no link, got %v", got)
	}
}

// TestExtractHTMLLinkBaseHref verifies relative links resolve against a <base
// href> when present, and that the base element's own href is not emitted.
func TestExtractHTMLLinkBaseHref(t *testing.T) {
	html := []byte(`<html><head><base href="/app/v2/"></head><body>
<a href="users/list">u</a>
<a href="/root/abs">r</a>
<a href="https://other.test/x">o</a>
</body></html>`)
	got := map[string]bool{}
	for _, m := range extractHTMLLinkMatches(html, "https://s.test/some/page") {
		got[m.Value] = true
	}
	want := []string{
		"https://s.test/app/v2/users/list", // resolved against <base>, not page path
		"https://s.test/root/abs",          // rooted path ignores base path
		"https://other.test/x",             // absolute unaffected
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %q; got %v", w, keysOf(got))
		}
	}
	// The <base> element's own href must not surface as a navigable link.
	if got["https://s.test/app/v2/"] {
		t.Errorf("<base> href leaked as an endpoint")
	}
	if len(got) != 3 {
		t.Errorf("expected exactly 3 links, got %d: %v", len(got), keysOf(got))
	}
}

// TestExtractHTMLLinkEdgeCases locks in correct handling of protocol-relative
// URLs, case-insensitive attributes, SVG xlink:href, multiple <base> elements
// (first wins, per the HTML spec) and whitespace around the '=' — so a future
// regex change cannot silently regress them.
func TestExtractHTMLLinkEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		html string
		want string
	}{
		{"protocol-relative", `<a href="//cdn.other.test/app.js">x</a>`, "https://cdn.other.test/app.js"},
		{"uppercase-attr", `<A HREF="/upper/case">x</A>`, "https://s.test/upper/case"},
		{"xlink-href", `<use xlink:href="/sprite.svg#icon"/>`, "https://s.test/sprite.svg"},
		{"multi-base-first-wins", `<base href="/first/"><base href="/second/"><a href="rel">x</a>`, "https://s.test/first/rel"},
		{"whitespace-around-eq", `<a href = "/spaced" >x</a>`, "https://s.test/spaced"},
	}
	for _, c := range cases {
		got := map[string]bool{}
		for _, m := range extractHTMLLinkMatches([]byte(c.html), "https://s.test/dir/page") {
			got[m.Value] = true
		}
		if !got[c.want] {
			t.Errorf("%s: expected %q, got %v", c.name, c.want, keysOf(got))
		}
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
