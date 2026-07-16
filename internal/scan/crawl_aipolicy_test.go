package scan

import (
	"reflect"
	"testing"

	"github.com/tavgar/JSMiner/internal/ai"
)

// TestFrontierPolicyReordersQueuedTargets verifies that installing a policy after
// targets are already queued re-scores them, so a policy-boosted URL is dequeued
// ahead of an equally-scored sibling that would otherwise win on insertion order.
func TestFrontierPolicyReordersQueuedTargets(t *testing.T) {
	f := newCrawlFrontier()
	// Two same-depth, same-base-score pages; without a policy /first.html pops
	// first (FIFO among equals).
	f.push(crawlTarget{url: "https://x.test/first.html", depth: 0})
	f.push(crawlTarget{url: "https://x.test/second.html", depth: 0})

	// Boost /second so it outscores /first, then confirm it now pops first.
	f.setPolicy(ai.Compile([]ai.Rule{{Pattern: `/second`, Weight: 50}}))

	if got := f.pop().url; got != "https://x.test/second.html" {
		t.Errorf("policy did not reorder queued targets: popped %q first", got)
	}
	if got := f.pop().url; got != "https://x.test/first.html" {
		t.Errorf("second pop = %q, want /first.html", got)
	}
}

// TestFrontierBreadthFirstBeatsPolicy confirms the policy only reorders within a
// depth level: a shallower target always precedes a deeper one no matter how large
// the deeper one's bonus.
func TestFrontierBreadthFirstBeatsPolicy(t *testing.T) {
	f := newCrawlFrontier()
	f.setPolicy(ai.Compile([]ai.Rule{{Pattern: `/deep`, Weight: 100}}))
	f.push(crawlTarget{url: "https://x.test/shallow.html", depth: 0})
	f.push(crawlTarget{url: "https://x.test/deep.js", depth: 1})
	if got := f.pop().depth; got != 0 {
		t.Errorf("breadth-first violated: popped depth %d first", got)
	}
}

func TestDirLevels(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"/api/v2/users", []string{"/", "/api/", "/api/v2/"}},
		{"/", []string{"/"}},
		{"/foo", []string{"/"}},
		{"/a/b/c/", []string{"/", "/a/", "/a/b/", "/a/b/c/"}},
	}
	for _, c := range cases {
		if got := dirLevels(c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("dirLevels(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestBuildSiteDigest(t *testing.T) {
	enqueued := map[string]struct{}{
		"https://x.test/":             {},
		"https://x.test/api/v2/users": {},
		"https://x.test/product/1":    {},
		"https://x.test/product/2":    {},
		"https://x.test/product/3":    {},
	}
	d := buildSiteDigest("https://x.test", enqueued)
	if d.Origin != "https://x.test" {
		t.Errorf("origin = %q", d.Origin)
	}
	// The three /product/N URLs collapse to one template class with count 3.
	var productKey string
	for k, c := range d.Counts {
		if c == 3 {
			productKey = k
		}
	}
	if productKey == "" {
		t.Errorf("expected a template class with 3 instances, got %v", d.Counts)
	}
	// The /api/ directory level should surface.
	found := false
	for _, l := range d.Levels {
		if l == "/api/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /api/ level in digest, got %v", d.Levels)
	}
	if d.Empty() {
		t.Error("digest should not be Empty")
	}
}
