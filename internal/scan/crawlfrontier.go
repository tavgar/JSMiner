package scan

import (
	"container/heap"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// crawlFrontier is the priority queue of pending crawl targets. It preserves the
// breadth-first contract — a shallower target is always dequeued before a deeper
// one — and, among targets at the same depth, dequeues higher-yield URLs first, so
// when MaxPages cuts a crawl off mid-level the budget was spent on the pages most
// likely to carry secrets and endpoints (JS bundles, JSON/API responses,
// extensionless routes) rather than on low-yield rendered listing pages. Insertion
// order breaks any remaining tie, so equal-priority targets keep first-in,
// first-out behaviour and the serial crawl stays deterministic.
type crawlFrontier struct {
	h *targetHeap
}

func newCrawlFrontier() *crawlFrontier {
	return &crawlFrontier{h: &targetHeap{}}
}

func (f *crawlFrontier) len() int { return f.h.Len() }

// push enqueues t, scoring it once from its URL so ordering costs nothing at pop.
func (f *crawlFrontier) push(t crawlTarget) {
	heap.Push(f.h, frontierItem{target: t, score: targetScore(t.url), seq: f.h.seq})
	f.h.seq++
}

// peek returns the highest-priority target without removing it. It must not be
// called on an empty frontier; the concurrent coordinator uses it to build a job
// it only commits (via pop) once the job is accepted by a worker.
func (f *crawlFrontier) peek() crawlTarget { return f.h.items[0].target }

// pop removes and returns the highest-priority target.
func (f *crawlFrontier) pop() crawlTarget { return heap.Pop(f.h).(frontierItem).target }

// snapshot returns the pending targets, in no particular order, so a crawl
// checkpoint can persist the frontier. Reloading them with push restores an
// equivalent priority order (the heap re-derives it from each target's depth and
// score), so resume order does not depend on how the heap happened to be laid out.
func (f *crawlFrontier) snapshot() []crawlTarget {
	out := make([]crawlTarget, 0, len(f.h.items))
	for _, it := range f.h.items {
		out = append(out, it.target)
	}
	return out
}

// frontierItem is a heap entry: the target, its precomputed yield score and the
// monotonic insertion sequence used as a stable final tiebreak.
type frontierItem struct {
	target crawlTarget
	score  int
	seq    int
}

// targetHeap implements container/heap.Interface ordered by (depth asc, score
// desc, seq asc). seq only ever increases, giving a stable FIFO tiebreak.
type targetHeap struct {
	items []frontierItem
	seq   int
}

func (h *targetHeap) Len() int { return len(h.items) }

func (h *targetHeap) Less(i, j int) bool {
	a, b := h.items[i], h.items[j]
	if a.target.depth != b.target.depth {
		return a.target.depth < b.target.depth // breadth-first: shallower first
	}
	// Live discoveries and site-published declarations carry stronger evidence
	// than third-party historical hints. Validate passive paths after ordinary
	// targets at the same depth so a tight page budget cannot crowd out the seed
	// or the current site's own link graph.
	if (a.target.passiveSource == "") != (b.target.passiveSource == "") {
		return a.target.passiveSource == ""
	}
	if a.score != b.score {
		return a.score > b.score // higher yield first within a depth level
	}
	return a.seq < b.seq // stable FIFO among equals
}

func (h *targetHeap) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }

func (h *targetHeap) Push(x any) { h.items = append(h.items, x.(frontierItem)) }

func (h *targetHeap) Pop() any {
	old := h.items
	n := len(old)
	it := old[n-1]
	h.items = old[:n-1]
	return it
}

// Yield scores, higher is fetched sooner within a depth level.
const (
	scoreAsset   = 100 // .js/.json/.map/.env/... : densest secrets and endpoints
	scoreAPI     = 90  // /api/, /graphql, /v1/, /oauth ... : API surface
	scoreRoute   = 70  // extensionless path: likely a page or API root
	scoreDefault = 50  // unknown or other
	scorePage    = 40  // .html/.php/... : rendered pages, least yield per fetch
)

// apiLikePathRe matches path segments that signal an API or otherwise
// high-interest surface, so those URLs are crawled before generic pages.
var apiLikePathRe = regexp.MustCompile(`(?i)(?:^|/)(?:api|graphql|graphiql|gql|rest|rpc|v[0-9]+|oauth2?|auth|token|gateway|internal|admin|config|settings|swagger|openapi|actuator|debug)(?:/|$|\.)`)

// targetScore rates how likely a URL is to carry secrets or fresh endpoints, so a
// capped crawl spends its budget on the densest targets first. The signal is cheap
// and URL-only: script, config and data files score highest, then API-shaped
// paths, then extensionless routes (likely pages or API roots), then rendered-page
// extensions, which yield the least per fetch.
func targetScore(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return scoreDefault
	}
	p := strings.ToLower(u.Path)
	ext := path.Ext(p)
	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map",
		".xml", ".yaml", ".yml", ".env", ".txt", ".config", ".ini", ".properties":
		return scoreAsset
	}
	if apiLikePathRe.MatchString(p) {
		return scoreAPI
	}
	if ext == "" {
		return scoreRoute
	}
	switch ext {
	case ".html", ".htm", ".xhtml", ".shtml", ".php", ".asp", ".aspx",
		".jsp", ".jspx", ".do", ".action", ".cfm":
		return scorePage
	}
	return scoreDefault
}
