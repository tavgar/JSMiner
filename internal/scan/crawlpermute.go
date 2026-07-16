package scan

import (
	"container/heap"
	"net/url"
	"path"
	"sort"
	"strings"
)

// permuter implements budget-aware cross-level path permutation for a crawl.
// Each origin gets its own pool so paths discovered on api.example.com are not
// silently replayed on www.example.com. Within an origin, newly learned path
// variants are combined with previously known directory levels and newly learned
// levels are combined with every known path, producing the incremental cross
// product exactly once.
//
// observe only proposes candidates. The crawl records an admission after the
// normal enqueue and template checks accept a URL, so duplicates and rejected
// templates do not consume PermuteMax.
type permuter struct {
	baseHost string
	max      int

	pools     map[string]*permuterPool
	poolOrder []string
	emitted   map[string]struct{}
	stats     permuterStats
}

type permuterPool struct {
	base *url.URL

	paths   []permutePath
	pathSet map[string]int
	levels  []string
	lvlSet  map[string]struct{}
	known   map[string]struct{}
	sources map[string]struct{}
}

// permutePath retains the escaped representation and query of a discovered URL.
// Keeping EscapedPath avoids turning an encoded slash (%2F) into a real path
// separator, while RawQuery preserves resources selected by query parameters.
type permutePath struct {
	EscapedPath string `json:"escaped_path"`
	RawQuery    string `json:"raw_query,omitempty"`
	Trimmed     int    `json:"trimmed,omitempty"`
	MountTrim   bool   `json:"mount_trim,omitempty"`
}

func (p permutePath) key() string {
	return p.EscapedPath + "\x00" + p.RawQuery
}

type permuteCandidate struct {
	URL   string
	Score int
}

type rankedCandidate struct {
	candidate permuteCandidate
	index     int
}

// candidateMinHeap keeps the worst retained candidate at the root so a better
// candidate can replace it in O(log n). For equal scores, a lexicographically
// larger URL is worse because final output uses URL ascending as its tiebreak.
type candidateMinHeap []*rankedCandidate

func (h candidateMinHeap) Len() int { return len(h) }
func (h candidateMinHeap) Less(i, j int) bool {
	a, b := h[i].candidate, h[j].candidate
	if a.Score != b.Score {
		return a.Score < b.Score
	}
	return a.URL > b.URL
}
func (h candidateMinHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *candidateMinHeap) Push(x any) {
	item := x.(*rankedCandidate)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *candidateMinHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	item.index = -1
	*h = old[:n-1]
	return item
}

type candidateCollector struct {
	limit  int
	heap   candidateMinHeap
	byURL  map[string]*rankedCandidate
	all    map[string]permuteCandidate
	pruned int
}

func newCandidateCollector(limit int) *candidateCollector {
	c := &candidateCollector{limit: limit}
	if limit > 0 {
		hint := limit
		if hint > 4096 {
			hint = 4096
		}
		c.byURL = make(map[string]*rankedCandidate, hint)
		return c
	}
	c.all = make(map[string]permuteCandidate)
	return c
}

func (c *candidateCollector) offer(candidate permuteCandidate) {
	if c.limit <= 0 {
		if old, exists := c.all[candidate.URL]; !exists || candidateBetter(candidate, old) {
			c.all[candidate.URL] = candidate
		}
		return
	}
	if old := c.byURL[candidate.URL]; old != nil {
		if candidateBetter(candidate, old.candidate) {
			old.candidate = candidate
			heap.Fix(&c.heap, old.index)
		}
		return
	}
	item := &rankedCandidate{candidate: candidate}
	if c.heap.Len() < c.limit {
		heap.Push(&c.heap, item)
		c.byURL[candidate.URL] = item
		return
	}
	if !candidateBetter(candidate, c.heap[0].candidate) {
		c.pruned++
		return
	}
	dropped := heap.Pop(&c.heap).(*rankedCandidate)
	delete(c.byURL, dropped.candidate.URL)
	c.pruned++
	heap.Push(&c.heap, item)
	c.byURL[candidate.URL] = item
}

func (c *candidateCollector) results() []permuteCandidate {
	var out []permuteCandidate
	if c.limit <= 0 {
		out = make([]permuteCandidate, 0, len(c.all))
		for _, candidate := range c.all {
			out = append(out, candidate)
		}
	} else {
		out = make([]permuteCandidate, 0, len(c.heap))
		for _, item := range c.heap {
			out = append(out, item.candidate)
		}
	}
	sort.Slice(out, func(i, j int) bool { return candidateBetter(out[i], out[j]) })
	return out
}

func candidateBetter(a, b permuteCandidate) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.URL < b.URL
}

// permuterStats is persisted with checkpoints so a resumed crawl retains both
// its admission budget and useful run-level accounting.
type permuterStats struct {
	Considered       int `json:"considered"`
	SkippedKnown     int `json:"skipped_known"`
	SkippedAdmission int `json:"skipped_admission"`
	Pruned           int `json:"pruned"`
	Admitted         int `json:"admitted"`
	Fetched          int `json:"fetched"`
	Yielded          int `json:"yielded"`
}

type permuterState struct {
	Pools   []permuterPoolState `json:"pools"`
	Emitted []string            `json:"emitted"`
	Stats   permuterStats       `json:"stats"`
}

type permuterPoolState struct {
	Origin string        `json:"origin"`
	Paths  []permutePath `json:"paths"`
	Levels []string      `json:"levels"`
	Known  []string      `json:"known"`
}

func newPermuter(origin, baseHost string, max int) *permuter {
	p := &permuter{
		baseHost: baseHost,
		max:      max,
		pools:    make(map[string]*permuterPool),
		emitted:  make(map[string]struct{}),
	}
	// Establish the seed origin up front. It remains empty until a real URL from
	// that origin is observed, but gives state snapshots a stable primary pool.
	if u, err := url.Parse(strings.TrimSuffix(origin, "/")); err == nil {
		p.ensurePool(u.Scheme + "://" + u.Host)
	}
	return p
}

// observe learns real URLs and returns the highest-value fresh permutations.
// Callers must never pass a synthetic page's own URL; targets genuinely found on
// such a page are fine because they are real discoveries. All URLs are registered
// as known before combinations are built, which filters identity permutations.
func (p *permuter) observe(targets []string) []permuteCandidate {
	if len(targets) == 0 {
		return nil
	}

	type poolDelta struct {
		pool          *permuterPool
		oldLevelCount int
		newPaths      []permutePath
		newLevels     []string
	}
	deltas := make(map[string]*poolDelta)
	var deltaOrder []string

	for _, raw := range targets {
		u, origin, ok := p.inScopeURL(raw)
		if !ok {
			continue
		}
		pool := p.ensurePool(origin)
		delta := deltas[origin]
		if delta == nil {
			delta = &poolDelta{pool: pool, oldLevelCount: len(pool.levels)}
			deltas[origin] = delta
			deltaOrder = append(deltaOrder, origin)
		}

		knownURL := normalizeCrawlURL(u.String())
		pool.known[knownURL] = struct{}{}
		pathVariants := permutationPathVariants(u)
		if len(pathVariants) > 0 {
			pool.sources[knownURL] = struct{}{}
		}
		for _, candidatePath := range pathVariants {
			key := candidatePath.key()
			if index, exists := pool.pathSet[key]; exists {
				if pathVariantBetter(candidatePath, pool.paths[index]) {
					pool.paths[index] = candidatePath
					delta.newPaths = append(delta.newPaths, candidatePath)
				}
				continue
			}
			pool.pathSet[key] = len(pool.paths)
			pool.paths = append(pool.paths, candidatePath)
			delta.newPaths = append(delta.newPaths, candidatePath)
		}
		for _, level := range levelsWithAncestors(u.String()) {
			if _, exists := pool.lvlSet[level]; exists {
				continue
			}
			pool.lvlSet[level] = struct{}{}
			pool.levels = append(pool.levels, level)
			delta.newLevels = append(delta.newLevels, level)
		}
	}

	// Even after the request budget is exhausted, retain newly learned state so a
	// checkpoint faithfully describes the crawl. There is simply nothing to emit.
	if !p.hasBudget() {
		return nil
	}

	collector := newCandidateCollector(p.candidateWindow())
	for _, origin := range deltaOrder {
		delta := deltas[origin]
		oldLevels := delta.pool.levels[:delta.oldLevelCount]

		// New paths × levels that existed before this observation.
		for _, candidatePath := range delta.newPaths {
			for _, level := range oldLevels {
				p.consider(collector, delta.pool, level, candidatePath)
			}
		}
		// New levels × all paths, including paths learned in this observation.
		for _, level := range delta.newLevels {
			for _, candidatePath := range delta.pool.paths {
				p.consider(collector, delta.pool, level, candidatePath)
			}
		}
	}

	out := collector.results()
	p.stats.Pruned += collector.pruned
	for _, candidate := range out {
		p.emitted[candidate.URL] = struct{}{}
	}
	return out
}

func (p *permuter) consider(collector *candidateCollector, pool *permuterPool, level string, candidatePath permutePath) {
	// A single real path only produces identity, ancestor and self-prefix guesses.
	// Wait for a second source so every origin starts with actual cross-path
	// evidence; the later observation still combines its new levels with old paths
	// and its new paths with old levels retroactively.
	if len(pool.sources) < 2 {
		return
	}
	raw, ok := buildPermutationURL(pool.base, level, candidatePath)
	if !ok {
		return
	}
	n := normalizeCrawlURL(raw)
	if _, exists := p.emitted[n]; exists {
		return
	}
	p.stats.Considered++

	if _, exists := pool.known[n]; exists {
		p.emitted[n] = struct{}{}
		p.stats.SkippedKnown++
		return
	}
	u, err := url.Parse(n)
	if err != nil || !crawlableTarget(u) {
		p.emitted[n] = struct{}{}
		return
	}
	collector.offer(permuteCandidate{
		URL:   n,
		Score: permutationScore(n, level, candidatePath),
	})
}

// hasBudget reports whether another successfully enqueued permutation may count
// against PermuteMax. Zero remains unlimited.
func (p *permuter) hasBudget() bool {
	return p != nil && (p.max <= 0 || p.stats.Admitted < p.max)
}

// recordAdmission accounts for the crawler's normal admission decision.
func (p *permuter) recordAdmission(admitted bool) {
	if admitted {
		p.stats.Admitted++
		return
	}
	p.stats.SkippedAdmission++
}

func (p *permuter) recordFetch(yielded bool) {
	p.stats.Fetched++
	if yielded {
		p.stats.Yielded++
	}
}

func (p *permuter) candidateWindow() int {
	if p.max <= 0 {
		return 0
	}
	remaining := p.max - p.stats.Admitted
	if remaining <= 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if remaining > (maxInt-64)/4 {
		return maxInt
	}
	return remaining*4 + 64
}

func (p *permuter) inScopeURL(raw string) (*url.URL, string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, "", false
	}
	if !sameScope(p.baseHost, u.Hostname()) {
		return nil, "", false
	}
	u.Fragment = ""
	return u, u.Scheme + "://" + u.Host, true
}

func (p *permuter) ensurePool(origin string) *permuterPool {
	if pool := p.pools[origin]; pool != nil {
		return pool
	}
	base, err := url.Parse(origin)
	if err != nil {
		return nil
	}
	pool := &permuterPool{
		base:    base,
		pathSet: make(map[string]int),
		lvlSet:  make(map[string]struct{}),
		known:   make(map[string]struct{}),
		sources: make(map[string]struct{}),
	}
	p.pools[origin] = pool
	p.poolOrder = append(p.poolOrder, origin)
	return pool
}

func buildPermutationURL(base *url.URL, level string, candidatePath permutePath) (string, bool) {
	if base == nil {
		return "", false
	}
	escapedPath := level + candidatePath.EscapedPath
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", false
	}
	u := *base
	u.Path = decodedPath
	u.RawPath = ""
	if u.EscapedPath() != escapedPath {
		u.RawPath = escapedPath
	}
	u.RawQuery = candidatePath.RawQuery
	u.Fragment = ""
	return u.String(), true
}

// permutationPathVariants produces a deliberately small set: the full relative
// path, the path after one likely mount prefix, its last two segments, and (for
// high-value assets and API endpoints) its basename. This catches common moves
// such as /legacy/admin/config.js becoming /api/admin/config.js or
// /api/config.js without an unbounded suffix explosion.
func permutationPathVariants(u *url.URL) []permutePath {
	escaped := strings.TrimPrefix(u.EscapedPath(), "/")
	if escaped == "" {
		return nil
	}
	trailingSlash := strings.HasSuffix(escaped, "/")
	segmentPath := strings.TrimSuffix(escaped, "/")
	segments := strings.Split(segmentPath, "/")
	suffix := ""
	if trailingSlash {
		suffix = "/"
	}
	var out []permutePath
	seen := make(map[string]struct{})
	add := func(candidate string, trimmed int, mountTrim bool) {
		if candidate == "" {
			return
		}
		pp := permutePath{EscapedPath: candidate, RawQuery: u.RawQuery, Trimmed: trimmed, MountTrim: mountTrim}
		if _, exists := seen[pp.key()]; exists {
			return
		}
		seen[pp.key()] = struct{}{}
		out = append(out, pp)
	}

	add(escaped, 0, false)
	if len(segments) > 1 && likelyMountSegment(segments[0]) {
		add(strings.Join(segments[1:], "/")+suffix, 1, true)
	}
	if len(segments) > 2 {
		add(strings.Join(segments[len(segments)-2:], "/")+suffix, len(segments)-2, false)
	}
	pathScore := targetScore(u.String())
	if len(segments) > 1 && (pathScore == scoreAsset || pathScore == scoreAPI) {
		add(segments[len(segments)-1]+suffix, len(segments)-1, false)
	}
	return out
}

func likelyMountSegment(escaped string) bool {
	segment, err := url.PathUnescape(escaped)
	if err != nil {
		segment = escaped
	}
	segment = strings.ToLower(segment)
	switch segment {
	case "api", "rest", "rpc", "legacy", "old", "public", "private",
		"static", "assets", "asset", "scripts", "script", "js", "src",
		"dist", "build", "app", "web":
		return true
	}
	if len(segment) >= 2 && segment[0] == 'v' {
		for i := 1; i < len(segment); i++ {
			if segment[i] < '0' || segment[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func pathVariantBetter(a, b permutePath) bool {
	aScore := -a.Trimmed * 150
	bScore := -b.Trimmed * 150
	if a.MountTrim {
		aScore += 500
	}
	if b.MountTrim {
		bScore += 500
	}
	return aScore > bScore
}

func permutationScore(rawURL, level string, candidatePath permutePath) int {
	score := targetScore(rawURL) * 100
	score -= candidatePath.Trimmed * 150
	score -= strings.Count(candidatePath.EscapedPath, "/") * 5
	if candidatePath.MountTrim {
		score += 500
	}

	levelSegment := lastPathSegment(level)
	pathSegment := firstPathSegment(candidatePath.EscapedPath)
	switch {
	case levelSegment == "":
		// Root-level permutations have less evidence of a genuine mount move.
		score -= 50
	case strings.EqualFold(levelSegment, pathSegment):
		// /api/ + api/users -> /api/api/users is legal, but usually low value.
		score -= 3000
	default:
		// Crossing distinct branches is the purpose of the feature.
		score += 200
	}
	return score
}

func firstPathSegment(escaped string) string {
	segment := strings.SplitN(strings.Trim(escaped, "/"), "/", 2)[0]
	if decoded, err := url.PathUnescape(segment); err == nil {
		return decoded
	}
	return segment
}

func lastPathSegment(escaped string) string {
	escaped = strings.Trim(escaped, "/")
	if escaped == "" {
		return ""
	}
	parts := strings.Split(escaped, "/")
	segment := parts[len(parts)-1]
	if decoded, err := url.PathUnescape(segment); err == nil {
		return decoded
	}
	return segment
}

// levelsWithAncestors returns escaped directory levels so encoded slashes remain
// data, not hierarchy. "/api/v2/users" yields ["/api/v2/", "/api/", "/"].
func levelsWithAncestors(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return []string{"/"}
	}
	escaped := u.EscapedPath()
	if escaped == "" {
		return []string{"/"}
	}
	level := path.Dir(escaped)
	if !strings.HasSuffix(level, "/") {
		level += "/"
	}
	var out []string
	for {
		out = append(out, level)
		if level == "/" {
			return out
		}
		parent := path.Dir(strings.TrimSuffix(level, "/"))
		if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
		level = parent
	}
}

func (p *permuter) snapshot() *permuterState {
	if p == nil {
		return nil
	}
	state := &permuterState{Stats: p.stats}
	for _, origin := range p.poolOrder {
		pool := p.pools[origin]
		ps := permuterPoolState{
			Origin: origin,
			Paths:  append([]permutePath(nil), pool.paths...),
			Levels: append([]string(nil), pool.levels...),
		}
		for known := range pool.known {
			ps.Known = append(ps.Known, known)
		}
		sort.Strings(ps.Known)
		state.Pools = append(state.Pools, ps)
	}
	for emitted := range p.emitted {
		state.Emitted = append(state.Emitted, emitted)
	}
	sort.Strings(state.Emitted)
	return state
}

func (p *permuter) restore(state *permuterState) {
	if p == nil || state == nil {
		return
	}
	p.pools = make(map[string]*permuterPool)
	p.poolOrder = nil
	p.emitted = make(map[string]struct{}, len(state.Emitted))
	p.stats = state.Stats

	for _, ps := range state.Pools {
		pool := p.ensurePool(ps.Origin)
		if pool == nil {
			continue
		}
		for _, candidatePath := range ps.Paths {
			if index, exists := pool.pathSet[candidatePath.key()]; exists {
				if pathVariantBetter(candidatePath, pool.paths[index]) {
					pool.paths[index] = candidatePath
				}
				continue
			}
			pool.pathSet[candidatePath.key()] = len(pool.paths)
			pool.paths = append(pool.paths, candidatePath)
		}
		for _, level := range ps.Levels {
			if _, exists := pool.lvlSet[level]; exists {
				continue
			}
			pool.lvlSet[level] = struct{}{}
			pool.levels = append(pool.levels, level)
		}
		for _, known := range ps.Known {
			pool.known[known] = struct{}{}
			if u, err := url.Parse(known); err == nil && len(permutationPathVariants(u)) > 0 {
				pool.sources[known] = struct{}{}
			}
		}
	}
	for _, emitted := range state.Emitted {
		p.emitted[emitted] = struct{}{}
	}
}
