package scan

import "testing"

// TestTargetScoreOrdering checks the yield tiers so a capped crawl prefers dense
// targets: scripts/JSON highest, then API-shaped paths, then extensionless routes,
// then rendered-page extensions.
func TestTargetScoreOrdering(t *testing.T) {
	cases := []struct {
		url  string
		want int
	}{
		{"https://x.com/static/app.9f2.js", scoreAsset},
		{"https://x.com/config.json", scoreAsset},
		{"https://x.com/app.js.map", scoreAsset},
		{"https://x.com/api/users", scoreAPI},
		{"https://x.com/graphql", scoreAPI},
		{"https://x.com/v2/orders", scoreAPI},
		{"https://x.com/dashboard", scoreRoute}, // extensionless page/route
		{"https://x.com/blog/2020/01/post.html", scorePage},
		{"https://x.com/index.php", scorePage},
		{"https://x.com/report.csv", scoreDefault}, // unknown text extension
	}
	for _, c := range cases {
		if got := targetScore(c.url); got != c.want {
			t.Errorf("targetScore(%s) = %d, want %d", c.url, got, c.want)
		}
	}
	// The relative ordering is what the frontier relies on.
	if !(scoreAsset > scoreAPI && scoreAPI > scoreRoute && scoreRoute > scoreDefault && scoreDefault > scorePage) {
		t.Fatal("yield tiers are not strictly ordered asset>api>route>default>page")
	}
}

// TestCrawlFrontierOrder verifies the frontier dequeues shallower targets first
// and, within a depth level, higher-yield targets before lower-yield ones, with
// insertion order breaking ties.
func TestCrawlFrontierOrder(t *testing.T) {
	f := newCrawlFrontier()
	// Push out of priority order and at mixed depths.
	f.push(crawlTarget{url: "https://x.com/about.html", depth: 1}) // page, depth 1
	f.push(crawlTarget{url: "https://x.com/api/users", depth: 1})  // api, depth 1
	f.push(crawlTarget{url: "https://x.com/app.js", depth: 1})     // asset, depth 1
	f.push(crawlTarget{url: "https://x.com/deep.js", depth: 2})    // asset, depth 2
	f.push(crawlTarget{url: "https://x.com/team", depth: 1})       // route, depth 1

	var order []string
	for f.len() > 0 {
		order = append(order, f.pop().url)
	}
	want := []string{
		"https://x.com/app.js",     // depth 1, asset (100)
		"https://x.com/api/users",  // depth 1, api (90)
		"https://x.com/team",       // depth 1, route (70)
		"https://x.com/about.html", // depth 1, page (40)
		"https://x.com/deep.js",    // depth 2 last, breadth-first
	}
	if !equalStrings(order, want) {
		t.Fatalf("frontier order = %v\nwant %v", order, want)
	}
}

// TestCrawlFrontierStableTie verifies equal (depth, score) targets keep insertion
// order, so the serial crawl stays deterministic.
func TestCrawlFrontierStableTie(t *testing.T) {
	f := newCrawlFrontier()
	f.push(crawlTarget{url: "https://x.com/a.js", depth: 0})
	f.push(crawlTarget{url: "https://x.com/b.js", depth: 0})
	f.push(crawlTarget{url: "https://x.com/c.js", depth: 0})
	got := []string{f.pop().url, f.pop().url, f.pop().url}
	want := []string{"https://x.com/a.js", "https://x.com/b.js", "https://x.com/c.js"}
	if !equalStrings(got, want) {
		t.Fatalf("stable tie order = %v, want %v", got, want)
	}
}

func TestCrawlFrontierAlwaysStartsWithRequestedSeed(t *testing.T) {
	f := newCrawlFrontier()
	f.push(crawlTarget{url: "https://x.com/", depth: 0, seed: true})
	f.push(crawlTarget{url: "https://x.com/.well-known/openid-configuration", depth: 0})
	f.push(crawlTarget{url: "https://x.com/sitemap.json", depth: 0})

	if got := f.pop().url; got != "https://x.com/" {
		t.Fatalf("frontier started with %s, want requested seed", got)
	}
}

func TestCrawlFrontierPrefersRealDiscoveryOverPermutation(t *testing.T) {
	f := newCrawlFrontier()
	f.push(crawlTarget{url: "https://x.com/guessed/config.js", depth: 1, permuted: true})
	f.push(crawlTarget{url: "https://x.com/dashboard", depth: 1})

	if got := f.pop().url; got != "https://x.com/dashboard" {
		t.Fatalf("frontier chose synthetic %s before direct discovery", got)
	}
}
