package scan

import (
	"net/url"
	"path"
	"strings"
)

// permuter implements cross-level path permutation for a crawl (the -crawl-permute
// feature). A normal crawl only fetches a discovered path where it was found; the
// permuter instead treats every discovered relative path as reusable and tries it
// under every directory level the crawl has seen, so a `/admin/panel` found on the
// seed is also attempted as `/api/admin/panel`, `/shop/admin/panel`, and so on.
//
// Both sets are global and grow as the crawl runs, and combinations are generated
// incrementally so a path discovered late (say at depth 3) is still combined with
// levels discovered earlier, and vice versa — the full cross product is produced
// exactly once regardless of discovery order. Generation is bounded by max so the
// paths×levels blow-up cannot run away; the crawl's page budget bounds it further.
type permuter struct {
	origin   string // scheme://host of the seed, no trailing slash
	baseHost string // seed hostname, for scope checks
	max      int    // cap on generated URLs (0 = unlimited)

	paths   []string            // discovered relative paths (no leading slash), ordered
	pathSet map[string]struct{} // dedup for paths
	levels  []string            // discovered directory levels (leading+trailing slash), ordered
	lvlSet  map[string]struct{} // dedup for levels

	emitted   map[string]struct{} // combinations already produced, so each is emitted once
	generated int                 // number of combinations emitted so far
}

func newPermuter(origin, baseHost string, max int) *permuter {
	return &permuter{
		origin:   strings.TrimSuffix(origin, "/"),
		baseHost: baseHost,
		max:      max,
		pathSet:  make(map[string]struct{}),
		lvlSet:   make(map[string]struct{}),
		emitted:  make(map[string]struct{}),
	}
}

// observe folds the page's in-scope next-hop targets into the global path and
// level sets and returns the fresh permutation URLs to enqueue. New paths are
// combined with the levels known before this call; new levels are then combined
// with every path (including the just-added ones), which together cover every new
// pairing exactly once without redoing old ones.
//
// Only the real discovered targets feed the sets — never the page's own URL. A
// synthetic permutation like /api/api/x that 404s yields no targets, so it cannot
// re-enter as a "discovered" path and drive unbounded deepening; real growth is
// still bounded by max and the crawl's page budget.
func (p *permuter) observe(targets []string) []string {
	if p.max > 0 && p.generated >= p.max {
		return nil
	}

	// Levels known before these targets contribute any new ones.
	oldLevels := p.levels

	// 1. Register new relative paths from the discovered targets.
	var newPaths []string
	for _, raw := range targets {
		if rp := relPath(raw); rp != "" {
			if _, ok := p.pathSet[rp]; !ok {
				p.pathSet[rp] = struct{}{}
				p.paths = append(p.paths, rp)
				newPaths = append(newPaths, rp)
			}
		}
	}

	// 2. Register new directory levels (each target's level plus its ancestors).
	var newLevels []string
	for _, raw := range targets {
		for _, lvl := range levelsWithAncestors(raw) {
			if _, ok := p.lvlSet[lvl]; !ok {
				p.lvlSet[lvl] = struct{}{}
				p.levels = append(p.levels, lvl)
				newLevels = append(newLevels, lvl)
			}
		}
	}

	var out []string
	// new paths × levels that already existed
	for _, rp := range newPaths {
		for _, lvl := range oldLevels {
			out = p.emit(out, lvl, rp)
			if p.max > 0 && p.generated >= p.max {
				return out
			}
		}
	}
	// new levels × all paths (old + new)
	for _, lvl := range newLevels {
		for _, rp := range p.paths {
			out = p.emit(out, lvl, rp)
			if p.max > 0 && p.generated >= p.max {
				return out
			}
		}
	}
	return out
}

// emit builds the combination origin+level+path, filters it the same way the
// normal crawl filters next hops (scope and non-crawlable assets), dedups it and,
// if it survives, appends it to out and counts it against the cap.
func (p *permuter) emit(out []string, level, rel string) []string {
	raw := p.origin + level + rel
	n := normalizeCrawlURL(raw)
	if _, ok := p.emitted[n]; ok {
		return out
	}
	p.emitted[n] = struct{}{}

	u, err := url.Parse(n)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return out
	}
	if !sameScope(p.baseHost, u.Hostname()) {
		return out
	}
	if !crawlableTarget(u) {
		return out
	}
	p.generated++
	return append(out, n)
}

// relPath returns the leading-slash-stripped path of rawURL, e.g. "/admin/panel"
// becomes "admin/panel". It returns "" for a root or unparseable URL, which has
// no path fragment worth permuting.
func relPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(u.Path, "/")
}

// levelsWithAncestors returns the directory level of rawURL together with all of
// its ancestor levels down to the root, each with a leading and trailing slash.
// "/api/v2/users" yields ["/api/v2/", "/api/", "/"].
func levelsWithAncestors(rawURL string) []string {
	lvl := levelOf(rawURL)
	var out []string
	for {
		out = append(out, lvl)
		if lvl == "/" {
			break
		}
		parent := path.Dir(strings.TrimSuffix(lvl, "/"))
		if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
		lvl = parent
	}
	return out
}
