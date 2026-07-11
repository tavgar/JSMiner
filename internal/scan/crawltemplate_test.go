package scan

import "testing"

func TestUrlTemplateKey(t *testing.T) {
	same := func(a, b string) {
		t.Helper()
		if urlTemplateKey(a) != urlTemplateKey(b) {
			t.Errorf("expected same template for %q and %q (got %q vs %q)",
				a, b, urlTemplateKey(a), urlTemplateKey(b))
		}
	}
	diff := func(a, b string) {
		t.Helper()
		if urlTemplateKey(a) == urlTemplateKey(b) {
			t.Errorf("expected different templates for %q and %q (both %q)",
				a, b, urlTemplateKey(a))
		}
	}

	// Numeric id segments collapse; the route name is kept.
	same("https://x.com/product/1", "https://x.com/product/2")
	same("https://x.com/product/1", "https://x.com/product/99999")
	// Paginated / faceted query URLs collapse on their parameter names.
	same("https://x.com/list?page=1", "https://x.com/list?page=2")
	same("https://x.com/search?color=red&size=9", "https://x.com/search?size=8&color=blue")
	// Calendar URLs collapse on the date segment.
	same("https://x.com/events/2024-01-01", "https://x.com/events/2025-12-31")
	// UUID and long hash ids collapse.
	same("https://x.com/u/550e8400-e29b-41d4-a716-446655440000",
		"https://x.com/u/550e8400-e29b-41d4-a716-446655440001")
	same("https://x.com/f/deadbeefcafe1234", "https://x.com/f/0123456789abcdef")

	// Genuinely different routes must not collapse.
	diff("https://x.com/product/1", "https://x.com/category/1")
	diff("https://x.com/list?page=1", "https://x.com/list?sort=name")
	// Short versioned route names are not data and stay distinct.
	diff("https://x.com/v1/users", "https://x.com/v2/users")
	diff("https://x.com/p0", "https://x.com/p1")
	// Different hosts are different templates.
	diff("https://a.com/product/1", "https://b.com/product/1")
}

func TestTemplateClasserAdmit(t *testing.T) {
	tc := newTemplateClasser(2)
	// First two instances of a class are admitted, the rest suppressed.
	if !tc.admit("https://x.com/product/1") {
		t.Fatal("first instance should be admitted")
	}
	if !tc.admit("https://x.com/product/2") {
		t.Fatal("second instance should be admitted")
	}
	if tc.admit("https://x.com/product/3") {
		t.Fatal("third instance should be suppressed by the cap")
	}
	// A different class is unaffected by another class's cap.
	if !tc.admit("https://x.com/article/1") {
		t.Fatal("a distinct class should still be admitted")
	}

	// A nil classer and a zero cap admit everything.
	var nilTC *templateClasser
	if !nilTC.admit("https://x.com/product/1") {
		t.Fatal("nil classer must admit")
	}
	if !newTemplateClasser(0).admit("https://x.com/product/1") {
		t.Fatal("zero cap must admit")
	}
}

func TestStructuralSig(t *testing.T) {
	// Same template, different data (ids, text) shares a signature.
	a := []byte(`<html><body><h1>Widget 1</h1><p>Cost: $10</p><a href="/buy/1">buy</a></body></html>`)
	b := []byte(`<html><body><h1>Gadget 2</h1><p>Cost: $99</p><a href="/buy/2">buy</a></body></html>`)
	if structuralSig(a) != structuralSig(b) {
		t.Fatalf("templated pages should share a structural signature:\n%q\n%q",
			structuralSig(a), structuralSig(b))
	}

	// A listing whose row count changes by a few still shares a signature.
	listing := func(rows int) []byte {
		s := "<html><body><ul>"
		for i := 0; i < rows; i++ {
			s += "<li><span>item</span></li>"
		}
		return []byte(s + "</ul></body></html>")
	}
	if structuralSig(listing(18)) != structuralSig(listing(22)) {
		t.Fatal("listings differing by a few rows should share a signature")
	}

	// Structurally different pages must not share a signature.
	c := []byte(`<html><body><form><input><input><button>go</button></form></body></html>`)
	if structuralSig(a) == structuralSig(c) {
		t.Fatal("structurally different pages must not share a signature")
	}

	// A big change in item count crosses a bucket boundary and separates classes.
	if structuralSig(listing(2)) == structuralSig(listing(200)) {
		t.Fatal("order-of-magnitude count differences should separate classes")
	}
}
