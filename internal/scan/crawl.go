package scan

import (
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// CrawlOptions configures a breadth-first crawl seeded from a single URL.
//
// A crawl scans the seed page, harvests the endpoints it discovers
// (endpoint_url/endpoint_path and, for POST crawls, post_url/post_path),
// resolves the in-scope ones to absolute URLs and fetches them too, repeating
// until the depth or page budget is exhausted. Each fetched page is scanned
// with the normal rules, so crawling reaches JavaScript bundles — and the
// secrets in them — that are only linked from deeper pages or API responses.
type CrawlOptions struct {
	// MaxDepth is the number of link hops to follow beyond the seed page. A
	// depth of 0 scans only the seed (matching a plain ScanURL); 1 also scans
	// endpoints found on the seed, and so on. A negative value means unlimited
	// depth: the crawl follows links until the link graph is exhausted (or the
	// page budget/scope stops it), which is what -crawl-all requests.
	MaxDepth int

	// MaxPages caps the total number of pages fetched by the crawl, protecting
	// against runaway link graphs and parameterised URL explosions. Zero means
	// no cap (bounded only by MaxDepth and scope).
	MaxPages int

	// SameScopeOnly restricts crawling to the seed host and its subdomains (see
	// sameScope). Off-scope endpoints are still reported when they surface as
	// matches, they are simply not crawled. This is the expected default: the
	// user asked to follow discovered URLs only when they match the host.
	SameScopeOnly bool

	// Permute turns on cross-level path permutation: every discovered relative
	// path is reused under every directory level the crawl has seen, so a path
	// found in one place is also tried under other levels on the same origin (see
	// permuter). A bounded set of useful suffix variants is considered too, and
	// candidates are ranked before enqueue. It is off by default because it
	// multiplies requests; PermuteMax bounds it.
	Permute bool

	// PermuteMax caps the number of path-permutation URLs successfully admitted
	// to the crawl. Already-known, duplicate and template-rejected URLs do not
	// consume it. Zero means no cap (bounded only by MaxPages and scope).
	PermuteMax int

	// AutoCalibrate turns on ffuf-style auto-calibration: before crawling, the
	// target is probed with random paths to learn its catch-all/soft-404
	// fingerprint, and pages matching that fingerprint — or duplicating a page
	// already scanned — are skipped so the crawl stays on unique, useful pages.
	// It defaults to on (see DefaultCrawlOptions); the CLI always enables it and
	// exposes no toggle. The field is retained so library callers and tests can
	// opt out.
	AutoCalibrate bool

	// ProbeMethods turns on multi-method probing: every page the crawl visits is
	// requested with each verb in RequestMethods, and the verbs that work — judged
	// against the per-method, per-level error logic learned by auto-calibration —
	// are reported as a gathered-URL finding. It defaults to on (see
	// DefaultCrawlOptions) and is off in a zero-value CrawlOptions so library
	// callers and existing tests are unaffected.
	ProbeMethods bool

	// RequestMethods lists the HTTP methods used by ProbeMethods. Empty means the
	// default set (GET, POST, PUT, PATCH, DELETE, OPTIONS).
	RequestMethods []string

	// ParamReplay turns on cross-level parameter replay: parameter bodies
	// discovered on POST/PUT/PATCH endpoints are replayed against every directory
	// level the crawl has seen, and replays that work against a level's learned
	// per-method error logic are reported as gathered-URL findings. It requires
	// ProbeMethods and defaults to on (see DefaultCrawlOptions); ParamReplayMax
	// bounds it.
	ParamReplay bool

	// ParamReplayMax caps the number of (level, parameter) replays generated when
	// ParamReplay is set. Zero means no cap (bounded only by scope and the crawl).
	ParamReplayMax int

	// TemplateDedup collapses templated duplicate pages — pages that are
	// structurally the same and differ only in data, such as /product/1 vs
	// /product/2, paginated listings and calendar/faceted URLs — so the crawl
	// fetches only a representative few of each class instead of every instance,
	// spending its page budget on genuinely distinct pages. It works on two
	// levels: discovered URLs are grouped by a normalised URL template before they
	// are fetched (see templateClasser), so a suppressed instance costs no request
	// at all; and fetched pages are additionally grouped by a structural body
	// signature (see structuralSig), catching templated pages whose URLs do not
	// reveal the pattern. It defaults to on (see DefaultCrawlOptions) and is off in
	// a zero-value CrawlOptions so library callers and existing tests are
	// unaffected. TemplateSampleMax bounds how many representatives are kept.
	TemplateDedup bool

	// TemplateSampleMax caps how many representative pages are crawled from each
	// template class when TemplateDedup is set. Zero selects a sensible default
	// (defaultTemplateSampleMax).
	TemplateSampleMax int

	// DiscoverWellKnown seeds the crawl from the URLs the site declares about
	// itself: robots.txt (Allow/Disallow directories and Sitemap: pointers) and
	// the XML sitemaps they and convention advertise (see discoverWellKnownURLs).
	// These are real, server-published paths, so they reach pages and API roots
	// that nothing links to and that static JS scanning never reveals. It defaults
	// to on (see DefaultCrawlOptions) and is off in a zero-value CrawlOptions so
	// library callers and existing tests are unaffected.
	DiscoverWellKnown bool

	// DiscoverPassive asks public web indexes for URLs historically observed on
	// the exact seed host. Historical URLs are path hints, not trusted targets:
	// query values are discarded, paths are rebased onto the current seed origin,
	// and each is accepted only when its live status and catch-all fingerprint
	// prove it still exists. A validated path becomes an ordinary real source for
	// Permute; rejected hints never enter its dictionary. It is opt-in because it
	// contacts third-party archives and adds validation requests to the target.
	DiscoverPassive bool

	// PassiveSources selects public indexes used by DiscoverPassive. Supported
	// values are "wayback" and "commoncrawl"; empty selects both.
	PassiveSources []string

	// PassiveMax caps the number of sanitized historical path hints admitted for
	// live validation. Values <= 0 select defaultPassiveMax; passive discovery is
	// never unbounded independently of the crawl's own page budget.
	PassiveMax int

	// OnDOMSourceHints receives sanitized source names learned outside response
	// bodies (currently archived query names). Values are never included. The CLI
	// uses this only when a later DOM scan is enabled.
	OnDOMSourceHints func([]DOMSourceHint)

	// ResumeFile, when non-empty, turns on crawl checkpointing: the crawl reloads
	// its state from this file at start (when it holds a checkpoint for the same
	// seed) and periodically writes its state back to it, so a run killed part way
	// through — the risk on a large -crawl-all — can be resumed instead of started
	// over. The file is removed on clean completion. Empty (the default) disables
	// checkpointing entirely.
	ResumeFile string

	// Concurrency is how many pages the crawl fetches and scans in parallel. A
	// crawl is dominated by per-page I/O — the HTTP fetch and, when rendering is
	// on, a headless-Chrome render that can take seconds — so processing several
	// pages at once is the main throughput win. Values <= 1 run the crawl serially
	// (the original, fully deterministic behaviour); higher values dispatch that
	// many pages to a worker pool. Per-host pacing and adaptive backoff (see
	// requestThrottle) still bound the load any single host sees, so raising this
	// speeds up render-heavy and multi-host crawls without abandoning politeness.
	// Note that with rendering on each worker may run its own browser, so the
	// setting also trades memory for speed. Zero means serial in a zero-value
	// CrawlOptions; DefaultCrawlOptions sets it to defaultCrawlConcurrency.
	Concurrency int

	// Progress, when non-nil, is invoked once per fetched page with the page
	// URL, its depth from the seed and the running page count. It lets the CLI
	// surface crawl progress without the scan package depending on the output
	// layer. During a concurrent crawl it is called as each page is dispatched, so
	// the page numbers stay monotonic even though pages then complete out of order.
	Progress func(pageURL string, depth, pageNum int)

	// OnCalibrated, when non-nil, is invoked once after auto-calibration with
	// the number of wildcard signatures learned.
	OnCalibrated func(wildcardSigs int)

	// OnComplete, when non-nil, is invoked once when the crawl finishes with a
	// summary of what it did (see CrawlStats). It lets the CLI print an
	// end-of-run report — pages fetched, targets discovered, errors, duration —
	// without the scan package depending on the output layer.
	OnComplete func(CrawlStats)
}

// CrawlStats summarises a completed crawl. It is reported once through
// CrawlOptions.OnComplete so operators get the run-level accounting an
// enterprise crawl is expected to surface — throughput, reach and failures —
// rather than only the per-page verbose narrative.
type CrawlStats struct {
	// PagesFetched is the number of pages whose fetch completed without a
	// transport/read error, including passive hints subsequently rejected by live
	// validation. PagesErrored is the number whose fetch or scan returned an error.
	PagesFetched int
	PagesErrored int

	// WellKnownSeeds is how many URLs the crawl seeded from robots.txt/sitemaps.
	WellKnownSeeds int

	// PassiveFound is the bounded number of sanitized historical path hints,
	// PassiveEnqueued is how many survived normal crawl dedup/template admission,
	// and Validated/Rejected report the result of live status + catch-all checks.
	PassiveFound     int
	PassiveEnqueued  int
	PassiveValidated int
	PassiveRejected  int

	// TargetsFound is the total in-scope crawl targets discovered across all
	// pages (with repeats), and Enqueued is the number of distinct pages that
	// were actually queued for crawling over the whole run.
	TargetsFound int
	Enqueued     int

	// Matches is the number of deduplicated matches the crawl returned, and
	// WildcardSigs is how many catch-all/soft-404 signatures auto-calibration
	// learned for the root.
	Matches      int
	WildcardSigs int

	// PermuteConsidered is the number of combinations evaluated.
	// PermuteEnqueued counts only candidates admitted by normal crawl dedup and
	// template checks, so it is the value bounded by PermuteMax. PermuteFetched
	// and PermuteYielded report how many synthetic pages were successfully scanned
	// and how many produced at least one match or fresh crawl target.
	PermuteConsidered       int
	PermuteSkippedKnown     int
	PermuteSkippedAdmission int
	PermutePruned           int
	PermuteEnqueued         int
	PermuteFetched          int
	PermuteYielded          int

	// Duration is the wall-clock time the crawl took.
	Duration time.Duration
}

// defaultCrawlConcurrency is how many pages a default interactive crawl fetches
// and scans in parallel. It is a modest fan-out: enough to hide per-page fetch
// and render latency, while keeping the number of concurrent headless-Chrome
// renders (one per busy worker) reasonable on an ordinary machine. Per-host
// pacing still bounds the load any single host sees.
const defaultCrawlConcurrency = 8

// DefaultCrawlOptions returns sensible defaults for interactive use: follow two
// hops beyond the seed, stay on the seed host, stop after 200 pages,
// auto-calibrate to suppress catch-all/soft-404 and duplicate pages, and fetch
// several pages in parallel.
func DefaultCrawlOptions() CrawlOptions {
	return CrawlOptions{
		MaxDepth: 2, MaxPages: 200, SameScopeOnly: true, AutoCalibrate: true,
		ProbeMethods: true, RequestMethods: defaultRequestMethods(),
		ParamReplay: true, ParamReplayMax: 500,
		TemplateDedup: true, TemplateSampleMax: defaultTemplateSampleMax,
		DiscoverWellKnown: true, PassiveMax: defaultPassiveMax,
		Concurrency: defaultCrawlConcurrency,
	}
}

// templateSampleMax returns the per-class representative cap to use for a crawl,
// falling back to the default when the option is left unset.
func templateSampleMax(opts CrawlOptions) int {
	if opts.TemplateSampleMax > 0 {
		return opts.TemplateSampleMax
	}
	return defaultTemplateSampleMax
}

// crawlTarget is a queued page together with its distance from the seed.
type crawlTarget struct {
	url           string
	depth         int
	permuted      bool
	passiveSource string
	seed          bool
}

// ScanURLCrawl scans urlStr and then crawls the in-scope endpoints it
// discovers, returning the deduplicated union of all matches. When endpoints is
// true only endpoint matches are produced (as with ScanURL). external controls
// whether off-scope script/import references are followed while scanning an
// individual page; the page-to-page crawl itself is governed by opts.
func (e *Extractor) ScanURLCrawl(urlStr string, endpoints, external, render bool, opts CrawlOptions) ([]Match, error) {
	scanPage := func(u, baseHost string, visited *visitedSet, validator *autoCalibrator) (scanURLResult, error) {
		return e.scanURLWithValidationDetailed(u, baseHost, endpoints, visited, external, render, validator)
	}
	return e.crawlBFS(urlStr, opts, scanPage)
}

// ScanURLPostsCrawl behaves like ScanURLCrawl but scans each page for HTTP POST
// request endpoints, following the discovered endpoints to reach deeper pages.
func (e *Extractor) ScanURLPostsCrawl(urlStr string, external, render bool, opts CrawlOptions) ([]Match, error) {
	scanPage := func(u, baseHost string, visited *visitedSet, validator *autoCalibrator) (scanURLResult, error) {
		return e.scanURLPostsWithValidationDetailed(u, baseHost, visited, external, render, validator)
	}
	return e.crawlBFS(urlStr, opts, scanPage)
}

// crawlBFS drives the breadth-first crawl. scanPage scans a single page (and,
// via scanURL/scanURLPosts, its script/import graph) and returns its matches;
// crawlBFS harvests fresh in-scope targets from those matches and keeps going.
//
// The visited map is shared across every scanPage call so a JS bundle
// referenced from many pages is fetched and scanned only once. The enqueued map
// tracks page-level targets so each page is crawled at most once.
func (e *Extractor) crawlBFS(seedURL string, opts CrawlOptions, scanPage func(u, baseHost string, visited *visitedSet, validator *autoCalibrator) (scanURLResult, error)) ([]Match, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, err
	}
	baseHost := seed.Hostname()

	origin := seed.Scheme + "://" + seed.Host

	crawlStart := time.Now()
	var stats CrawlStats

	var perm *permuter
	if opts.Permute {
		perm = newPermuter(origin, baseHost, opts.PermuteMax)
	}

	// A single calibrator backs both whole-page auto-calibration (skipPage) and
	// per-method probing, so the two share the level fingerprints they learn. It
	// is created whenever either feature is active.
	var cal *autoCalibrator
	if opts.AutoCalibrate || opts.ProbeMethods || opts.DiscoverPassive {
		cal = newAutoCalibrator()
		cal.setBase(seed.String())
	}
	if opts.AutoCalibrate {
		// Structural body dedup rides on the calibrator, which is only installed
		// (and consulted by skipPage) when auto-calibration is active.
		if opts.TemplateDedup {
			cal.enableStructuralDedup(templateSampleMax(opts))
		}
		vlog(1, "[crawl] auto-calibrating against %s", seed.String())
		n := cal.calibrate(seed.String())
		stats.WildcardSigs = n
		e.SetCalibrator(cal)
		defer e.SetCalibrator(nil)
		vlog(1, "[crawl] calibration learned %d wildcard signature(s)", n)
		if opts.OnCalibrated != nil {
			opts.OnCalibrated(n)
		}
	}

	methods := normalizeMethods(opts.RequestMethods)
	var replay *paramReplayer
	if opts.ProbeMethods && opts.ParamReplay {
		replay = newParamReplayer(origin, opts.ParamReplayMax)
	}

	// The template classer groups discovered URLs by page template and admits only
	// a representative few of each, so /product/1…/product/N and paginated or
	// faceted URLs do not each consume a fetch and a slot in the page budget.
	var classer *templateClasser
	if opts.TemplateDedup {
		classer = newTemplateClasser(templateSampleMax(opts))
	}

	visited := newVisitedSet()
	enqueued := make(map[string]struct{})

	start := normalizeCrawlURL(seed.String())
	frontier := newCrawlFrontier()

	var all []Match
	pages := 0
	// crawlDelayForCheckpoint is the robots.txt Crawl-delay (as a per-host floor)
	// carried through the checkpoint, so a resumed run re-establishes the same
	// pacing without re-fetching robots.txt.
	var crawlDelayForCheckpoint time.Duration

	// Resume from a checkpoint when one is configured and matches this seed;
	// otherwise seed the crawl normally.
	resumed := false
	if opts.ResumeFile != "" {
		cp, err := readCheckpoint(opts.ResumeFile)
		switch {
		case err != nil:
			// Absent/unreadable/old checkpoint: start fresh (this is the first run).
		case cp.Seed != start:
			vlog(1, "[crawl] checkpoint %s is for a different seed (%s); starting fresh", opts.ResumeFile, cp.Seed)
		default:
			visited.addAll(cp.Visited)
			for _, e := range cp.Enqueued {
				enqueued[e] = struct{}{}
			}
			hasPendingPassive := false
			for _, ct := range cp.Frontier {
				frontier.push(crawlTarget{
					url: ct.URL, depth: ct.Depth, permuted: ct.Permuted,
					passiveSource: ct.PassiveSource, seed: ct.Seed,
				})
				hasPendingPassive = hasPendingPassive || ct.PassiveSource != ""
			}
			// The checkpoint carries target provenance. Keep strict validation on
			// even if a resumed library caller did not repeat DiscoverPassive in
			// its options; otherwise a pending historical hint could silently turn
			// into a trusted ordinary page after restart.
			if hasPendingPassive && cal == nil {
				cal = newAutoCalibrator()
				cal.setBase(seed.String())
			}
			if perm != nil {
				perm.restore(cp.Permuter)
			}
			all = cp.Matches
			pages = cp.Pages
			stats.PassiveFound = cp.Passive.Found
			stats.PassiveEnqueued = cp.Passive.Enqueued
			stats.PassiveValidated = cp.Passive.Validated
			stats.PassiveRejected = cp.Passive.Rejected
			crawlDelayForCheckpoint = time.Duration(cp.CrawlDelayMS) * time.Millisecond
			if crawlDelayForCheckpoint > 0 {
				SetHostRateFloor(baseHost, crawlDelayForCheckpoint)
			}
			resumed = true
			vlog(1, "[crawl] resumed from %s: %d page(s) done, %d queued, %d visited, %d match(es)",
				opts.ResumeFile, pages, frontier.len(), len(cp.Visited), len(all))
		}
	}

	if !resumed {
		frontier.push(crawlTarget{url: start, depth: 0, seed: true})
		enqueued[start] = struct{}{}
		// The seed is always crawled; register it so it counts toward its own class.
		classer.admit(start)

		// Seed from the site's own declarations (robots.txt / sitemaps) so the crawl
		// reaches server-published paths that nothing links to. They enter at depth 0,
		// like the seed, so their own discovered links get the full depth budget.
		if opts.DiscoverWellKnown {
			wkURLs, crawlDelay := discoverWellKnownURLs(origin)
			crawlDelayForCheckpoint = crawlDelay
			// Honour the site's robots.txt Crawl-delay as a per-host pacing floor, so
			// the crawl never requests faster than the site asked for. It is combined
			// with (never lowers) any -rate-limit the user set and, per the throttle's
			// own logic, staying under the limit protects secret recall by keeping
			// pages from coming back as 429 shells.
			if crawlDelay > 0 {
				SetHostRateFloor(baseHost, crawlDelay)
				vlog(1, "[crawl] honouring robots.txt Crawl-delay %s for %s", crawlDelay, baseHost)
			}
			for _, raw := range wkURLs {
				u, err := url.Parse(raw)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
					continue
				}
				if opts.SameScopeOnly && !sameScope(baseHost, u.Hostname()) {
					continue
				}
				if !crawlableTarget(u) {
					continue
				}
				n := normalizeCrawlURL(u.String())
				if _, ok := enqueued[n]; ok {
					continue
				}
				if !classer.admit(n) {
					continue
				}
				enqueued[n] = struct{}{}
				frontier.push(crawlTarget{url: n, depth: 0})
				vlog(1, "[crawl] well-known seed %s", n)
			}
			stats.WellKnownSeeds = frontier.len() - 1
			vlog(1, "[crawl] seeded %d URL(s) from robots.txt/sitemaps", stats.WellKnownSeeds)
		}

		// Public archive URLs are historical hints, so they are admitted as
		// validation targets rather than trusted discoveries. Their archived query
		// values have already been stripped and their paths rebased onto `origin`.
		// The page scanner will reject stale/error/catch-all responses before they
		// can produce findings, next hops, method probes or permutation input.
		if opts.DiscoverPassive {
			passive := discoverPassiveURLs(seed, opts.PassiveSources, opts.PassiveMax)
			if opts.OnDOMSourceHints != nil {
				var hints []DOMSourceHint
				for _, candidate := range passive {
					provenance := DOMHintPassiveWayback
					if candidate.Source == passiveSourceCommonCrawl {
						provenance = DOMHintPassiveCommon
					}
					for _, name := range candidate.ParamNames {
						hints = append(hints, DOMSourceHint{
							Kind: SourceURLQuery, Name: name, Discovered: []string{provenance},
						})
					}
				}
				opts.OnDOMSourceHints(hints)
			}
			stats.PassiveFound = len(passive)
			// Bound repeated historical templates without consuming the live
			// classer's quota. Only a path that later validates is enrolled in the
			// main classer, so stale /product/{id} hints cannot suppress current
			// URLs discovered from the site's own content.
			var passiveClasser *templateClasser
			if opts.TemplateDedup {
				passiveClasser = newTemplateClasser(templateSampleMax(opts))
			}
			for _, candidate := range passive {
				if _, ok := enqueued[candidate.URL]; ok {
					continue
				}
				if !passiveClasser.admit(candidate.URL) {
					continue
				}
				enqueued[candidate.URL] = struct{}{}
				frontier.push(crawlTarget{
					url: candidate.URL, depth: 0, passiveSource: candidate.Source,
				})
				stats.PassiveEnqueued++
				vlog(1, "[crawl] passive hint (%s) %s", candidate.Source, candidate.URL)
			}
			vlog(1, "[crawl] admitted %d/%d passive URL hint(s) for live validation",
				stats.PassiveEnqueued, stats.PassiveFound)
		}
	}

	// admit records a discovered next-hop URL as queued, applying the same
	// already-queued and template-class limits both drivers share. It is only ever
	// called from the single goroutine that owns the queue (the serial loop, or the
	// concurrent coordinator), so it needs no lock.
	admit := func(next string) bool {
		if _, ok := enqueued[next]; ok {
			vlog(3, "[crawl] skip (already queued) %s", next)
			return false
		}
		if !classer.admit(next) {
			vlog(3, "[crawl] skip (template dedup) %s", next)
			return false
		}
		enqueued[next] = struct{}{}
		return true
	}

	// enqueuePermutations teaches the permuter only URLs that survived a live
	// fetch and page validation. A broad JavaScript match is still queued and
	// checked normally, but it cannot multiply into hundreds of cross-level guesses
	// before proving it exists. This is important for bundled module tables and
	// schema keywords that look path-like: validation preserves every direct
	// discovery while preventing false positives from amplifying the request load.
	// A synthetic page never teaches its own URL; any direct target it reveals is
	// validated later as an ordinary crawl target before it enters the dictionary.
	enqueuePermutations := func(t crawlTarget) {
		if perm == nil || (opts.MaxDepth >= 0 && t.depth >= opts.MaxDepth) {
			return
		}
		if t.permuted {
			return
		}
		for _, candidate := range perm.observe([]string{t.url}) {
			if !perm.hasBudget() {
				break
			}
			accepted := admit(candidate.URL)
			perm.recordAdmission(accepted)
			if !accepted {
				continue
			}
			frontier.push(crawlTarget{url: candidate.URL, depth: t.depth + 1, permuted: true})
			vlog(3, "[crawl] enqueue permuted depth %d score %d %s", t.depth+1, candidate.Score, candidate.URL)
		}
	}

	// saveCheckpoint persists the crawl's recoverable state so a killed run can be
	// resumed. inflight are pages dispatched but not yet completed (the concurrent
	// driver's in-flight jobs; nil for the serial driver): they are written back
	// into the frontier and excluded from the visited snapshot, so the checkpoint
	// stays self-consistent — every persisted page is either fully done (visited,
	// its matches in `all`) or still pending (queued, not visited) — and a resume
	// re-fetches the in-flight pages cleanly rather than skipping them. It is called
	// only from the goroutine that owns the crawl state (serial loop or concurrent
	// coordinator), so reading that state needs no lock; visited snapshots itself.
	saveCheckpoint := func(inflight []crawlTarget) {
		if opts.ResumeFile == "" {
			return
		}
		vis := visited.snapshot()
		if len(inflight) > 0 {
			exclude := make(map[string]struct{}, len(inflight))
			for _, t := range inflight {
				exclude[t.url] = struct{}{}
			}
			kept := vis[:0]
			for _, u := range vis {
				if _, skip := exclude[u]; !skip {
					kept = append(kept, u)
				}
			}
			vis = kept
		}
		cp := crawlCheckpoint{
			Version: crawlCheckpointVersion,
			Seed:    start,
			// `pages` counts dispatches so the live coordinator can enforce its
			// budget. In-flight pages are also persisted back onto the frontier;
			// counting them here as completed would make a capped resumed crawl
			// refuse to dispatch them. Persist only fully completed dispatches.
			Pages:        checkpointCompletedPages(pages, len(inflight)),
			CrawlDelayMS: crawlDelayForCheckpoint.Milliseconds(),
			Visited:      vis,
			Enqueued:     mapKeys(enqueued),
			Matches:      all,
			Permuter:     perm.snapshot(),
			Passive: passiveCheckpointStats{
				Found: stats.PassiveFound, Enqueued: stats.PassiveEnqueued,
				Validated: stats.PassiveValidated, Rejected: stats.PassiveRejected,
			},
		}
		for _, t := range frontier.snapshot() {
			cp.Frontier = append(cp.Frontier, checkpointTarget{
				URL: t.url, Depth: t.depth, Permuted: t.permuted,
				PassiveSource: t.passiveSource, Seed: t.seed,
			})
		}
		for _, t := range inflight {
			cp.Frontier = append(cp.Frontier, checkpointTarget{
				URL: t.url, Depth: t.depth, Permuted: t.permuted,
				PassiveSource: t.passiveSource, Seed: t.seed,
			})
		}
		if err := writeCheckpoint(opts.ResumeFile, cp); err != nil {
			vlog(1, "[crawl] checkpoint write failed: %v", err)
		} else {
			vlog(2, "[crawl] checkpoint written to %s (%d done, %d queued)", opts.ResumeFile, cp.Pages, len(cp.Frontier))
		}
	}

	if opts.Concurrency > 1 {
		// Concurrent crawl. A pool of workers fetches and scans pages — and probes
		// their methods and parameter replays — in parallel, while this goroutine
		// acts as the sole coordinator: it owns the queue, the enqueue/template
		// bookkeeping, the permutation and parameter-replay accumulators, the stats
		// and the match list, so none of that needs a lock. Workers only touch the
		// pieces that are already synchronised — the shared HTTP path, the visited
		// set and the calibrator — so the shared visited set still fetches a bundle
		// linked from several pages once, and the calibrator's per-level fingerprints
		// are still shared across the whole crawl. Pages complete out of order, so
		// the visit order (and, once MaxPages caps the run, exactly which pages fall
		// outside the budget) is no longer deterministic; the depth budget, scope and
		// page budget still bound the crawl the same way.
		workers := opts.Concurrency

		// A job is either a page to fetch+scan or a parameter replay to probe. Replay
		// probing is HTTP-bound too, so it rides the same pool instead of blocking
		// the coordinator on network I/O.
		type crawlJob struct {
			page     crawlTarget
			replay   replayTarget
			isReplay bool
		}
		// A result carries the matches to record and, for a page, the harvested
		// next-hop targets and discovered parameters the coordinator needs to grow
		// the crawl. targets/params are computed in the worker — they are pure
		// functions of the page's matches — so the coordinator's turn stays short.
		type crawlResult struct {
			job        crawlJob
			matches    []Match
			targets    []string
			params     []string
			accepted   bool
			skipReason pageSkipReason
			err        error
		}

		jobCh := make(chan crawlJob)
		resultCh := make(chan crawlResult, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobCh {
					if job.isReplay {
						worked := probeParamReplayMethods(cal, job.replay.url, methods, job.replay.params)
						var ms []Match
						if gm, ok := gatheredMatch(job.replay.url, worked, job.replay.params); ok {
							vlog(3, "[crawl] param-replay %s params=%s -> methods %s", job.replay.url, job.replay.params, strings.Join(worked, ","))
							ms = append(ms, gm)
						}
						resultCh <- crawlResult{job: job, matches: ms}
						continue
					}
					t := job.page
					var validator *autoCalibrator
					if t.passiveSource != "" {
						validator = cal
					}
					pageResult, err := scanPage(t.url, baseHost, visited, validator)
					if err != nil {
						resultCh <- crawlResult{job: job, err: err}
						continue
					}
					if !pageResult.accepted {
						resultCh <- crawlResult{job: job}
						continue
					}
					ms := pageResult.matches
					out := ms
					// Report which request methods this page accepts, judged against
					// the per-method error logic learned for its level.
					if opts.ProbeMethods && !pageResult.skipped {
						if worked := probeURLMethodsWithBaseline(cal, t.url, methods, "", pageResult.baseline); worked != nil {
							vlog(3, "[crawl] probe %s -> methods %s", t.url, strings.Join(worked, ","))
							if gm, ok := gatheredMatch(t.url, worked, ""); ok {
								if t.passiveSource != "" {
									gm.Params += " passive_source=" + t.passiveSource
								}
								out = append(out, gm)
							}
						}
						// A GraphQL endpoint: confirm it and map its schema surface by
						// sending an introspection query.
						if isGraphQLEndpoint(t.url) {
							if gm, ok := probeGraphQLIntrospection(t.url); ok {
								vlog(1, "[crawl] graphql introspection enabled at %s", t.url)
								out = append(out, gm)
							}
						}
					}
					// A negative MaxDepth means unlimited depth; otherwise stop
					// harvesting next hops once the depth cap is reached.
					var targets, params []string
					if opts.MaxDepth < 0 || t.depth < opts.MaxDepth {
						targets = crawlTargetsFromMatches(ms, t.url, baseHost, opts)
						params = paramsFromMatches(ms)
					}
					resultCh <- crawlResult{
						job: job, matches: out, targets: targets, params: params,
						accepted: true, skipReason: pageResult.skipReason,
					}
				}
			}()
		}

		var replayQueue []replayTarget
		pending := 0 // jobs dispatched but not yet completed
		// inFlight tracks pages dispatched but not yet completed, keyed by URL, so a
		// checkpoint can persist them as still-pending (see saveCheckpoint).
		inFlight := make(map[string]crawlTarget)
		sinceCheckpoint := 0 // completed pages since the last checkpoint write

		for {
			// Drain replay probes (they never grow the crawl) before dispatching new
			// pages, and only dispatch a page while under the page budget. pages counts
			// all page dispatches — including those restored from a checkpoint — so the
			// budget holds across a resume.
			var (
				job     crawlJob
				haveJob bool
			)
			switch {
			case len(replayQueue) > 0:
				job = crawlJob{isReplay: true, replay: replayQueue[0]}
				haveJob = true
			case frontier.len() > 0 && (opts.MaxPages <= 0 || pages < opts.MaxPages):
				job = crawlJob{page: frontier.peek()}
				haveJob = true
			}

			if !haveJob && pending == 0 {
				break // nothing left to dispatch and nothing in flight
			}

			// Disable the send case when there is no job ready, so the coordinator
			// only waits for results; the receive case is always live while work is
			// in flight, which is what keeps the pipeline deadlock-free.
			sendCh := jobCh
			if !haveJob {
				sendCh = nil
			}

			select {
			case sendCh <- job:
				pending++
				if job.isReplay {
					replayQueue = replayQueue[1:]
				} else {
					frontier.pop()
					inFlight[job.page.url] = job.page
					pages++
					if opts.Progress != nil {
						opts.Progress(job.page.url, job.page.depth, pages)
					}
					vlog(1, "[crawl] (%d) depth %d fetching %s", pages, job.page.depth, job.page.url)
				}
			case res := <-resultCh:
				pending--
				if res.job.isReplay {
					all = append(all, res.matches...)
					continue
				}
				t := res.job.page
				delete(inFlight, t.url)
				if res.err != nil {
					if t.passiveSource != "" {
						stats.PassiveRejected++
					}
					stats.PagesErrored++
					vlog(1, "[crawl] depth %d %s -> error: %v", t.depth, t.url, res.err)
					continue
				}
				stats.PagesFetched++
				if !res.accepted {
					if t.passiveSource != "" {
						stats.PassiveRejected++
					}
					continue
				}
				if t.passiveSource != "" {
					stats.PassiveValidated++
					classer.admit(t.url)
					vlog(1, "[crawl] validated passive path (%s) %s", t.passiveSource, t.url)
				}
				all = append(all, res.matches...)
				stats.TargetsFound += len(res.targets)
				if perm != nil && t.permuted {
					perm.recordFetch(len(res.matches) > 0 || len(res.targets) > 0)
				}
				vlog(1, "[crawl] %s -> %d match(es), %d in-scope target(s)", t.url, len(res.matches), len(res.targets))

				// Replay this page's parameters against every level seen so far, and
				// its levels against every parameter seen so far; the actual probing
				// happens on the worker pool via the replay jobs queued here.
				if replay != nil {
					levelURLs := make([]string, 0, len(res.targets)+1)
					levelURLs = append(levelURLs, res.targets...)
					levelURLs = append(levelURLs, t.url)
					replayQueue = append(replayQueue, replay.observe(res.params, levelURLs)...)
				}
				for _, next := range res.targets {
					if admit(next) {
						frontier.push(crawlTarget{url: next, depth: t.depth + 1})
						vlog(3, "[crawl] enqueue depth %d %s", t.depth+1, next)
					}
				}
				if res.skipReason != pageSkipWildcard {
					enqueuePermutations(t)
				}
				// Checkpoint periodically, re-queuing the still-in-flight pages so the
				// snapshot is self-consistent.
				if sinceCheckpoint++; opts.ResumeFile != "" && sinceCheckpoint >= crawlCheckpointInterval {
					sinceCheckpoint = 0
					flight := make([]crawlTarget, 0, len(inFlight))
					for _, ft := range inFlight {
						flight = append(flight, ft)
					}
					saveCheckpoint(flight)
				}
			}
		}
		close(jobCh)
		wg.Wait()
	} else {
		for frontier.len() > 0 {
			if opts.MaxPages > 0 && pages >= opts.MaxPages {
				break
			}
			t := frontier.pop()
			pages++
			if opts.Progress != nil {
				opts.Progress(t.url, t.depth, pages)
			}
			vlog(1, "[crawl] (%d) depth %d fetching %s", pages, t.depth, t.url)

			var validator *autoCalibrator
			if t.passiveSource != "" {
				validator = cal
			}
			pageResult, err := scanPage(t.url, baseHost, visited, validator)
			if err != nil {
				if t.passiveSource != "" {
					stats.PassiveRejected++
				}
				stats.PagesErrored++
				vlog(1, "[crawl] (%d) depth %d %s -> error: %v", pages, t.depth, t.url, err)
				continue
			}
			ms := pageResult.matches
			accepted := pageResult.accepted
			stats.PagesFetched++
			if !accepted {
				if t.passiveSource != "" {
					stats.PassiveRejected++
				}
				continue
			}
			if t.passiveSource != "" {
				stats.PassiveValidated++
				classer.admit(t.url)
				vlog(1, "[crawl] validated passive path (%s) %s", t.passiveSource, t.url)
			}
			all = append(all, ms...)
			if perm != nil && t.permuted {
				perm.recordFetch(len(ms) > 0)
			}
			vlog(1, "[crawl] (%d) %s -> %d match(es)", pages, t.url, len(ms))

			// Report which request methods this page accepts, judged against the
			// per-method error logic learned for its level.
			if opts.ProbeMethods && !pageResult.skipped {
				if worked := probeURLMethodsWithBaseline(cal, t.url, methods, "", pageResult.baseline); worked != nil {
					vlog(3, "[crawl] probe %s -> methods %s", t.url, strings.Join(worked, ","))
					if gm, ok := gatheredMatch(t.url, worked, ""); ok {
						if t.passiveSource != "" {
							gm.Params += " passive_source=" + t.passiveSource
						}
						all = append(all, gm)
					}
				}
				// A GraphQL endpoint: confirm it and map its schema surface by sending
				// an introspection query.
				if isGraphQLEndpoint(t.url) {
					if gm, ok := probeGraphQLIntrospection(t.url); ok {
						vlog(1, "[crawl] graphql introspection enabled at %s", t.url)
						all = append(all, gm)
					}
				}
			}

			// A negative MaxDepth means unlimited depth, so only the page budget and
			// scope bound the crawl; otherwise stop harvesting once the cap is hit.
			if opts.MaxDepth >= 0 && t.depth >= opts.MaxDepth {
				continue
			}
			targets := crawlTargetsFromMatches(ms, t.url, baseHost, opts)
			stats.TargetsFound += len(targets)
			vlog(1, "[crawl] %s -> %d in-scope target(s) discovered", t.url, len(targets))

			// Replay parameters discovered on this page against every level seen so
			// far, and this page's levels against every parameter seen so far; keep
			// the replays that work against each level's learned per-method logic.
			if replay != nil {
				// Include this page's own URL so its directory level is registered even
				// when nothing under it was discovered as a crawl target.
				levelURLs := make([]string, 0, len(targets)+1)
				levelURLs = append(levelURLs, targets...)
				levelURLs = append(levelURLs, t.url)
				for _, rt := range replay.observe(paramsFromMatches(ms), levelURLs) {
					worked := probeParamReplayMethods(cal, rt.url, methods, rt.params)
					if gm, ok := gatheredMatch(rt.url, worked, rt.params); ok {
						vlog(3, "[crawl] param-replay %s params=%s -> methods %s", rt.url, rt.params, strings.Join(worked, ","))
						all = append(all, gm)
					}
				}
			}
			for _, next := range targets {
				if admit(next) {
					frontier.push(crawlTarget{url: next, depth: t.depth + 1})
					vlog(3, "[crawl] enqueue depth %d %s", t.depth+1, next)
				}
			}
			if pageResult.skipReason != pageSkipWildcard {
				enqueuePermutations(t)
			}
			// Checkpoint periodically. The serial loop fully processes each page
			// before the next, so there are no in-flight pages to re-queue.
			if opts.ResumeFile != "" && pages%crawlCheckpointInterval == 0 {
				saveCheckpoint(nil)
			}
		}
	}

	// The crawl reached this point without being killed, so it is complete: there
	// is nothing left to resume, and leaving the checkpoint behind would make the
	// next run wrongly resume a finished crawl. Remove it.
	if opts.ResumeFile != "" {
		removeCheckpoint(opts.ResumeFile)
	}

	out := UniqueMatches(all)
	if opts.OnComplete != nil {
		stats.Enqueued = len(enqueued)
		stats.Matches = len(out)
		if perm != nil {
			stats.PermuteConsidered = perm.stats.Considered
			stats.PermuteSkippedKnown = perm.stats.SkippedKnown
			stats.PermuteSkippedAdmission = perm.stats.SkippedAdmission
			stats.PermutePruned = perm.stats.Pruned
			stats.PermuteEnqueued = perm.stats.Admitted
			stats.PermuteFetched = perm.stats.Fetched
			stats.PermuteYielded = perm.stats.Yielded
		}
		stats.Duration = time.Since(crawlStart)
		opts.OnComplete(stats)
	}
	return out, nil
}

// crawlTargetsFromMatches derives the next set of crawlable page URLs from the
// matches found on pageURL. Endpoint, POST and `path` values are resolved
// against the origin they were found in — the match's own source URL when that
// is an absolute http(s) location, otherwise the page URL — then filtered to
// http(s), optionally constrained to the seed scope and stripped of obvious
// binary assets that would waste a fetch. Resolving against the source matters
// for relative values lifted from a cross-origin bundle (e.g. `/settings.json`
// in a third-party consent script): they belong to that bundle's host, so they
// resolve off-scope and are dropped rather than being misattributed to the seed
// host as bogus 404 targets. `path` matches are included so that genuine paths
// surfaced by the power rule (not just JS endpoints) are followed too; they have
// already passed validPathMatch, and non-web values such as Windows paths fall
// out at the scheme check below.
func crawlTargetsFromMatches(ms []Match, pageURL, baseHost string, opts CrawlOptions) []string {
	suppressedContextPaths := bundledContextPaths(ms)
	seen := make(map[string]struct{})
	var out []string
	for _, m := range ms {
		switch m.Pattern {
		case "endpoint_url", "endpoint_path", "post_url", "post_path", "path":
		default:
			continue
		}
		// `path` values retain a leading space from the rule's `(?:^|\s)` anchor;
		// trim before resolving so the reference parses correctly.
		raw := strings.TrimSpace(m.Value)
		if raw == "" {
			continue
		}
		if _, skip := suppressedContextPaths[m.Source+"\x00"+raw]; skip {
			vlog(3, "[crawl] skip bundled module-context path %s from %s", raw, m.Source)
			continue
		}
		abs := resolveURL(resolveBase(m.Source, pageURL), raw)
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if opts.SameScopeOnly && !sameScope(baseHost, u.Hostname()) {
			continue
		}
		if !crawlableTarget(u) {
			continue
		}
		n := normalizeCrawlURL(u.String())
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// bundledContextPaths recognises the dense extensionless/.js key pairs emitted
// into webpack-style module context tables. A bundle containing "./af" +
// "./af.js", "./ar" + "./ar.js", and hundreds more is enumerating modules that
// are already inside the bundle; those strings are not server endpoints. Mining
// them as findings remains useful, but crawling every key against the website
// creates hundreds of guaranteed soft-404s and can crowd real URLs out of the
// page budget. Requiring at least eight pairs from one source keeps ordinary
// relative paths (including a lone dynamic import) fully crawlable.
func bundledContextPaths(ms []Match) map[string]struct{} {
	const minContextPairs = 8

	bySource := make(map[string]map[string]struct{})
	for _, m := range ms {
		switch m.Pattern {
		case "endpoint_path", "post_path", "path":
		default:
			continue
		}
		raw := strings.TrimSpace(m.Value)
		if m.Source == "" || !strings.HasPrefix(raw, "./") || strings.ContainsAny(raw, "?#") {
			continue
		}
		if bySource[m.Source] == nil {
			bySource[m.Source] = make(map[string]struct{})
		}
		bySource[m.Source][raw] = struct{}{}
	}

	suppressed := make(map[string]struct{})
	for source, paths := range bySource {
		var pairs [][2]string
		for raw := range paths {
			ext := strings.ToLower(path.Ext(raw))
			switch ext {
			case ".js", ".mjs", ".cjs":
			default:
				continue
			}
			stem := strings.TrimSuffix(raw, path.Ext(raw))
			if _, ok := paths[stem]; ok {
				pairs = append(pairs, [2]string{stem, raw})
			}
		}
		if len(pairs) < minContextPairs {
			continue
		}
		for _, pair := range pairs {
			suppressed[source+"\x00"+pair[0]] = struct{}{}
			suppressed[source+"\x00"+pair[1]] = struct{}{}
		}
	}
	return suppressed
}

// resolveBase picks the URL that a match's relative value should be resolved
// against. A value harvested from an external script belongs to that script's
// origin, not the page that referenced it, so when source is an absolute http(s)
// URL it wins. Inline scripts and other non-URL sources (e.g. "inline.js") have
// no origin of their own and fall back to the page URL, whose origin they share.
func resolveBase(source, pageURL string) string {
	if u, err := url.Parse(source); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return source
	}
	return pageURL
}

// normalizeCrawlURL canonicalises a URL for crawl bookkeeping by dropping the
// fragment, which never changes what the server returns. The query is retained
// because it can select a distinct resource; the page budget bounds any
// parameter explosion.
func normalizeCrawlURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	return u.String()
}

// nonCrawlableExts are asset types that cannot yield further JavaScript,
// endpoints or secrets, so fetching them during a crawl is pure overhead.
var nonCrawlableExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {}, ".webp": {},
	".ico": {}, ".bmp": {}, ".tiff": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
	".mp4": {}, ".webm": {}, ".mp3": {}, ".wav": {}, ".ogg": {}, ".avi": {},
	".mov": {}, ".mkv": {},
	".zip": {}, ".gz": {}, ".tar": {}, ".rar": {}, ".7z": {}, ".bz2": {},
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {},
	".pptx": {},
}

// crawlableTarget reports whether u is worth fetching during a crawl. Binary
// assets (images, fonts, media, archives, documents) are skipped; everything
// else — HTML pages, JS, JSON, extensionless routes and API paths — is kept.
func crawlableTarget(u *url.URL) bool {
	ext := strings.ToLower(path.Ext(u.Path))
	if ext == "" {
		return true
	}
	_, skip := nonCrawlableExts[ext]
	return !skip
}
