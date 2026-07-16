package ai

import "testing"

func TestCompactDeterministicAndBounded(t *testing.T) {
	d := SiteDigest{
		Origin:    "https://x.test",
		Templates: []string{"x.test/product/{}", "x.test/api/v2/users", "x.test/product/{}", " "},
		Counts:    map[string]int{"x.test/product/{}": 42, "x.test/api/v2/users": 1},
		Levels:    []string{"/api/", "/", "/api/"},
		Samples:   []string{"https://x.test/b", "https://x.test/a", "https://x.test/a"},
	}
	c1 := d.Compact()
	c2 := d.Compact()

	// Determinism: same input, byte-identical fingerprints.
	if c1.Fingerprint("m") != c2.Fingerprint("m") {
		t.Error("Compact/Fingerprint not deterministic")
	}
	// Dedup + sort of templates.
	if len(c1.Templates) != 2 {
		t.Fatalf("templates = %v, want 2 unique", c1.Templates)
	}
	if c1.Templates[0] > c1.Templates[1] {
		t.Errorf("templates not sorted: %v", c1.Templates)
	}
	// Counts are retained only for surviving templates.
	if c1.Counts["x.test/product/{}"] != 42 {
		t.Errorf("count lost after compact: %v", c1.Counts)
	}
	// Levels/samples deduped.
	if len(c1.Levels) != 2 || len(c1.Samples) != 2 {
		t.Errorf("levels=%v samples=%v; want 2 each", c1.Levels, c1.Samples)
	}
}

func TestFingerprintVariesWithModelAndStructure(t *testing.T) {
	d := SiteDigest{Origin: "https://x.test", Templates: []string{"x.test/api"}, Counts: map[string]int{"x.test/api": 1}}
	if d.Fingerprint("haiku") == d.Fingerprint("opus") {
		t.Error("fingerprint should depend on model id")
	}
	d2 := SiteDigest{Origin: "https://x.test", Templates: []string{"x.test/api", "x.test/admin"}, Counts: map[string]int{"x.test/api": 1, "x.test/admin": 1}}
	if d.Fingerprint("haiku") == d2.Fingerprint("haiku") {
		t.Error("fingerprint should depend on discovered structure")
	}
}

func TestEmpty(t *testing.T) {
	if !(SiteDigest{Origin: "https://x.test"}).Empty() {
		t.Error("digest with no templates/levels/samples should be Empty")
	}
	if (SiteDigest{Templates: []string{"x.test/api"}}).Empty() {
		t.Error("digest with a template should not be Empty")
	}
}
