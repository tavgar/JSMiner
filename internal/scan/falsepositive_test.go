package scan

import "testing"

func TestCredentialValueFilter(t *testing.T) {
	// Real, secret-looking values on the RHS should pass.
	keep := []string{
		`api-key":"lGj7N3xYpt7By9ZMJTxf32RoRs3B1uvt8JzwJgai"`,
		`password="Sup3rS3cretP@ssw0rd"`,
		`password="secretpass"`,
		`token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`,
	}
	for _, s := range keep {
		if !credentialValueFilter(s) {
			t.Errorf("expected keep, dropped: %q", s)
		}
	}

	// Minified identifiers, booleans, keywords, kebab and dictionary words drop.
	drop := []string{
		`password:!0,range:!0`,
		`Password:ie`,
		`Password=uI`,
		`password:a.password`,
		`username:e`,
		`username:o`,
		`token:Zt`,
		`token:new`,
		`_tokenizer=void`,
		`tokenize:function`,
		`tokens:Object`,
		`data-token-hash="css-var-root"`,
		`"password":"text"`,
	}
	for _, s := range drop {
		if credentialValueFilter(s) {
			t.Errorf("expected drop, kept: %q value=%q", s, credentialValue(s))
		}
	}
}

func TestIPv4RuleContext(t *testing.T) {
	rule := newIPv4Rule()
	find := func(s string) []Match { return rule.Find([]byte(s)) }

	// Isolated, real addresses are kept.
	for _, s := range []string{"host=10.0.0.5;", "connect 203.0.113.42 now", "1.2.3.4", `"192.168.1.10"`} {
		if len(find(s)) == 0 {
			t.Errorf("expected ipv4 match in %q", s)
		}
	}

	// Decimal streams (SVG paths / coordinate arrays / versions) are rejected.
	for _, s := range []string{
		"38.13.44.25.57.17.8.2",
		"1.11.16.2 57.17.8.2 39.11.65.14",
		"v1.2.3.4.5",
		"05.09.12.12", // leading zeros -> not even a valid quad
	} {
		if got := find(s); len(got) != 0 {
			t.Errorf("expected no ipv4 in %q, got %v", s, got)
		}
	}
}

func TestIPv6Filter(t *testing.T) {
	keep := []string{"2001:db8::1", "2001:0db8:0000:0000:0000:ff00:0042:8329", "fe80:0:0:0:0:0:0:1"}
	for _, s := range keep {
		if !validIPv6Match(s) {
			t.Errorf("expected keep ipv6 %q", s)
		}
	}
	// CSS pseudo-selector fragments ("::before"->"::bef") and short forms drop.
	drop := []string{"::", "::f", "::af", "::bef", "e::af", "ed::bef", "12:34:56"}
	for _, s := range drop {
		if validIPv6Match(s) {
			t.Errorf("expected drop ipv6 %q", s)
		}
	}
}

func TestPathFilter(t *testing.T) {
	keep := []string{"/tmp/data", " /vc-ap-vercel-marketing/_next/image", "/usr/local/bin"}
	for _, s := range keep {
		if !validPathMatch(s) {
			t.Errorf("expected keep path %q", s)
		}
	}
	drop := []string{"/_", "/___", "/_/_/_", "/g", "/i", `t:\s*([\w-]+)`, "/404"}
	for _, s := range drop {
		if validPathMatch(s) {
			t.Errorf("expected drop path %q", s)
		}
	}
}

func TestEndpointValidation(t *testing.T) {
	keepURL := []string{
		"https://6hov9rjope.execute-api.us-west-2.amazonaws.com/dev",
		"https://api.internal.corp/v2/users",
		"https://valid.com/api",
	}
	for _, s := range keepURL {
		if !validEndpointURL(s) {
			t.Errorf("expected keep url %q", s)
		}
	}
	dropURL := []string{
		"http://localhost",
		"https://...",
		"https://react.dev/errors/",
		"https://github.com/syntax-tree/hast-util-to-jsx-runtime",
		"https://quilljs.com",
		"http://a",
		"//",
	}
	for _, s := range dropURL {
		if validEndpointURL(s) {
			t.Errorf("expected drop url %q", s)
		}
	}

	keepPath := []string{"/issue", "/user-delete", "/business-hours", "/v2/data", "./b.js", "../parent/api"}
	for _, s := range keepPath {
		if !validEndpointPath(s) {
			t.Errorf("expected keep path %q", s)
		}
	}
	dropPath := []string{"/&", "/,", "/([^/]+)", "/_root.", "/g,", "/..", "/></svg>", "/./", "/$"}
	for _, s := range dropPath {
		if validEndpointPath(s) {
			t.Errorf("expected drop path %q", s)
		}
	}
}
