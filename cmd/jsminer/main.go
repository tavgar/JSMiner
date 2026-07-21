package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"plugin"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tavgar/JSMiner/internal/output"
	"github.com/tavgar/JSMiner/internal/proxy"
	"github.com/tavgar/JSMiner/internal/scan"
)

type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, ",") }
func (h *headerSlice) Set(v string) error {
	*h = append(*h, v)
	return nil
}

const version = "0.01v"

// reorderFlagArgs moves recognized flags (and their values) before positional
// arguments so Go's standard flag parser accepts the documented
// `jsminer target -flag=value` form. The standard parser stops at the first
// positional argument; preprocessing avoids maintaining a second, incomplete
// flag parser and keeps all flags working identically on either side of targets.
func reorderFlagArgs(args []string, fs *flag.FlagSet) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		rawName := strings.TrimLeft(arg, "-")
		name, hasInlineValue := rawName, false
		if before, _, ok := strings.Cut(rawName, "="); ok {
			name, hasInlineValue = before, true
		}
		f := fs.Lookup(name)
		if f == nil {
			// Let flag.Parse produce its normal "flag provided but not defined"
			// error, including for an unknown flag written after a target.
			flags = append(flags, arg)
			continue
		}
		if hasInlineValue {
			flags = append(flags, arg)
			continue
		}

		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			// Preserve the historically accepted `-render false` spelling, but
			// consume the following token only when it is actually a boolean.
			if i+1 < len(args) {
				if v, err := strconv.ParseBool(args[i+1]); err == nil {
					flags = append(flags, arg+"="+strconv.FormatBool(v))
					i++
					continue
				}
			}
			flags = append(flags, arg)
			continue
		}

		flags = append(flags, arg)
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

func main() {
	format := flag.String("format", "pretty", "output format: pretty, json or jsonl (NDJSON streaming)")
	safe := flag.Bool("safe", false, "safe mode - only scan JS")
	allowFile := flag.String("allow", "", "allowlist file")
	rulesFile := flag.String("rules", "", "extra regex rules YAML")
	endpoints := flag.Bool("endpoints", false, "only return HTTP endpoints")
	posts := flag.Bool("posts", false, "only return HTTP POST request endpoints")
	external := flag.Bool("external", true, "follow external scripts and imports")
	redirect := flag.Bool("redirect", false, "follow HTTP redirects")
	render := flag.Bool("render", true, "render pages in headless Chrome")
	insecure := flag.Bool("insecure", true, "skip TLS certificate verification")
	longSecret := flag.Bool("longsecret", false, "detect generic long secrets")
	outFile := flag.String("output", "", "output file (stdout default)")
	quiet := flag.Bool("quiet", false, "suppress banner")
	proxyAddr := flag.String("proxy", "", "run as proxy on address (e.g., :8080)")
	crawl := flag.Bool("crawl", false, "crawl in-scope endpoints/paths discovered on each page to reach more JS and secrets")
	full := flag.Bool("full", false, "full discovery mode: enables -crawl, -crawl-passive and -crawl-permute")
	crawlDepth := flag.Int("crawl-depth", 2, "max link hops to follow beyond the seed page in crawl/full mode")
	crawlAll := flag.Bool("crawl-all", false, "crawl to unlimited depth until no new in-scope pages remain (still bounded by -crawl-max-pages; pair with -crawl-max-pages 0 for no page cap)")
	crawlMaxPages := flag.Int("crawl-max-pages", 200, "max pages to fetch during a crawl (0 = unlimited)")
	crawlWorkers := flag.Int("crawl-workers", 8, "pages to fetch/scan in parallel during a crawl (1 = serial; each busy worker may run its own headless-Chrome render)")
	crawlResume := flag.String("crawl-resume", "", "checkpoint file for a resumable crawl: if it holds a checkpoint for the same seed the crawl continues from it, and progress is saved to it periodically (removed on clean completion)")
	crawlPermute := flag.Bool("crawl-permute", false, "reuse discovered paths and useful suffixes across directory levels on the same origin (multiplies requests; capped by -crawl-permute-max)")
	crawlPermuteMax := flag.Int("crawl-permute-max", 1000, "max permuted URLs admitted to the crawl (0 = unlimited)")
	methods := flag.String("methods", "", "comma-separated HTTP methods to probe each crawled URL with (default: GET,POST,PUT,PATCH,DELETE,OPTIONS)")
	noMethods := flag.Bool("no-methods", false, "disable multi-method probing / gathered-URL reporting during a crawl")
	noParamReplay := flag.Bool("no-param-replay", false, "disable replaying discovered parameters across every directory level during a crawl")
	noTemplateDedup := flag.Bool("no-template-dedup", false, "disable collapsing templated duplicate pages (/product/1 vs /product/2, paginated/faceted URLs) during a crawl")
	noWellKnown := flag.Bool("no-well-known", false, "disable seeding a crawl from the site's robots.txt and XML sitemaps")
	crawlPassive := flag.Bool("crawl-passive", false, "gather historical paths from public web indexes, validate them live, and use validated paths in crawl permutations")
	crawlPassiveSources := flag.String("crawl-passive-sources", "wayback,commoncrawl", "comma-separated passive URL sources: wayback,commoncrawl")
	crawlPassiveMax := flag.Int("crawl-passive-max", 100, "max historical path hints admitted for live validation (values <= 0 use 100)")
	templateSampleMax := flag.Int("template-sample-max", 3, "max representative pages to crawl per templated class when template dedup is on")
	noSourceMaps := flag.Bool("no-source-maps", false, "disable recovering original source from JavaScript source maps advertised by scanned bundles")
	targetsFile := flag.String("targets", "", "file with list of targets")
	pluginsFlag := flag.String("plugins", "", "comma-separated plugin files")
	showSourceFlag := flag.Bool("show-source", false, "show source of each record (auto-enabled for multiple targets)")
	snippet := flag.Bool("snippet", false, "show a JS-prettified, syntax-highlighted code snippet around each finding")
	timeout := flag.Int("timeout", 8, "wait time in seconds for dynamic content to load when rendering pages (default: 8)")
	httpTimeout := flag.Int("http-timeout", 10, "per-request timeout in seconds for HTTP fetches (page/script fetches, calibration and method probes, sitemaps)")
	retries := flag.Int("retries", 2, "extra attempts for a bodyless HTTP fetch that fails with a transient transport error (0 = no retries)")
	verbose1 := flag.Bool("v", false, "verbose: crawl narrative — matches per page, targets discovered, calibration/dedup skips")
	verbose2 := flag.Bool("vv", false, "more verbose: also log every HTTP request/response and page render (implies -v)")
	verbose3 := flag.Bool("vvv", false, "trace: also log per-target enqueue/skip, method probes, param replays and permutations (implies -vv)")
	exploreStates := flag.Int("explore-states", 12, "when rendering, max additional application states to reach through interaction — client-side navigation and filled/submitted forms (0 = render each page once)")
	rateLimit := flag.Float64("rate-limit", 0, "max HTTP requests per second per host (0 = no proactive limit; adaptive 429/503 backoff and rate-limit-header pre-emption are always on)")
	rateLimitJitter := flag.Float64("rate-limit-jitter", 0, "randomise each inter-request gap by +/- this fraction (e.g. 0.2 = +/-20%) to avoid a lockstep cadence (0 = off)")
	chromePath := flag.String("chrome-path", "", "path to the Chrome/Chromium executable for rendering (default: auto-detect on PATH; also honours $JSMINER_CHROME)")
	downloadBrowser := flag.Bool("download-browser", false, "provision the bundled Chromium now (download if needed) and print its path, then exit if no target is given")
	noDownloadBrowser := flag.Bool("no-download-browser", false, "never download a Chromium; only use -chrome-path, a bundled or cached browser, or one on PATH")
	browserDest := flag.String("browser-dest", "", "with -download-browser, extract Chromium into <dir>/chromium so <dir> (binary + chromium/) ships as a self-contained bundle")

	// DOM vulnerability scanning (opt-in; disabled by default and never enabled by
	// -full). It reuses the same target handling, scope, headers, cookies, TLS,
	// redirects, throttling, timeouts and Chromium configuration as the rest of the
	// scanner, and applies only to URL targets where browser rendering is available.
	dom := flag.Bool("dom", false, "enable DOM vulnerability scanning (DOM XSS source-to-sink flows + postMessage analysis) for URL targets; renders and instruments pages in headless Chrome")
	domMode := flag.String("dom-mode", "canary", "DOM scan mode: observe (record sink activity, change nothing), canary (inject non-executing markers and report flows), confirm (controlled, non-visible confirmation probes)")
	domMaxPages := flag.Int("dom-max-pages", 50, "max pages to DOM-scan (0 = unlimited; bounds runaway link graphs independently of -crawl-max-pages)")
	domMaxProbes := flag.Int("dom-max-probes", 1000, "max DOM probes across the whole scan, so a page or app cannot cause unbounded probes (0 = unlimited)")
	domWorkers := flag.Int("dom-workers", 4, "DOM pages to scan in parallel (independent of -crawl-workers)")
	domTimeout := flag.Int("dom-timeout", 25, "per-page DOM scan budget in seconds")
	domSources := flag.String("dom-sources", "", "comma-separated source families to probe (default all): url_query,url_fragment,referrer,window_name,form_input,cookie,local_storage,session_storage,web_message")
	domSinks := flag.String("dom-sinks", "", "comma-separated sink families to hook (default all): innerHTML,outerHTML,insertAdjacentHTML,document.write,srcdoc,eval,Function,setTimeout,script.src,navigation,event-handler")
	domMessages := flag.Bool("dom-messages", true, "analyse postMessage (listeners, messages, origin/source inspection, cross-origin leaks) as part of a DOM scan")
	domAllowExternal := flag.Bool("dom-allow-external", false, "allow DOM navigation and probes to reach third-party origins and follow client-side redirects out of scope")
	failOn := flag.String("fail-on", "", "exit non-zero when a finding at or above this severity is present: info|low|medium|high (empty = exit 1 on any finding)")

	var headerFlags headerSlice
	flag.Var(&headerFlags, "header", "HTTP header in 'Key: Value' format. May be repeated")
	if err := flag.CommandLine.Parse(reorderFlagArgs(os.Args[1:], flag.CommandLine)); err != nil {
		log.Fatal(err)
	}
	leftover := flag.Args()

	// Browser provisioning must be configured before any render (or an explicit
	// -download-browser) resolves a browser. An explicit -chrome-path wins;
	// otherwise fall back to $JSMINER_CHROME so a browser installed off PATH
	// (common in CI images and containers) is still used.
	if *chromePath == "" {
		*chromePath = os.Getenv("JSMINER_CHROME")
	}
	scan.SetChromePath(*chromePath)
	if *noDownloadBrowser {
		scan.SetAutoDownloadBrowser(false)
	}
	// Surface browser provisioning (chiefly the large first-run download) so the
	// scan does not appear to hang while Chromium downloads.
	if !*quiet {
		scan.BrowserNotice = func(msg string) { fmt.Fprintln(os.Stderr, "jsminer: "+msg) }
	}
	if *downloadBrowser {
		var (
			p   string
			err error
		)
		if *browserDest != "" {
			// Build a self-contained bundle: place chromium next to a copy of the
			// binary in <dir>/chromium.
			p, err = scan.ProvisionBundle(*browserDest)
		} else {
			p = scan.ResolveBrowser()
			if p == "" {
				err = fmt.Errorf("could not locate or download a Chromium for rendering")
			}
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "browser: "+p)
		// Provision-only invocation: nothing else to do without a target.
		if len(leftover) == 0 && *targetsFile == "" && *proxyAddr == "" {
			os.Exit(0)
		}
	}

	var targets []string
	if *proxyAddr == "" && *targetsFile != "" {
		f, err := os.Open(*targetsFile)
		if err != nil {
			log.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			targets = append(targets, t)
		}
		if err := sc.Err(); err != nil {
			log.Fatal(err)
		}
		f.Close()
	}
	if *proxyAddr == "" {
		targets = append(targets, leftover...)
	}
	if *proxyAddr == "" && len(targets) == 0 {
		if !*quiet {
			fmt.Fprintln(os.Stderr, output.Banner(version))
		}
		fmt.Fprintln(os.Stderr, "usage: jsminer [URL|PATH|-] [flags]")
		os.Exit(2)
	}

	if *pluginsFlag != "" {
		for _, pl := range strings.Split(*pluginsFlag, ",") {
			pl = strings.TrimSpace(pl)
			if pl == "" {
				continue
			}
			if _, err := plugin.Open(pl); err != nil {
				log.Fatal(err)
			}
		}
	}

	if len(headerFlags) > 0 {
		h := http.Header{}
		for _, hv := range headerFlags {
			parts := strings.SplitN(hv, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key != "" {
				h.Add(key, val)
			}
		}
		scan.SetExtraHeaders(h)
	}

	// Set the render timeout if specified
	if *timeout > 0 {
		scan.SetRenderSleepDuration(*timeout)
	}
	scan.SetMaxExploreStates(*exploreStates)
	scan.SetSkipTLSVerification(*insecure)
	scan.SetFollowRedirects(*redirect)
	scan.SetHTTPTimeout(*httpTimeout)
	scan.SetFetchRetries(*retries)
	scan.SetRateLimit(*rateLimit)
	scan.SetRateLimitJitter(*rateLimitJitter)

	// -v/-vv/-vvv are cumulative: the highest one given wins, and each level
	// implies the ones below it.
	verbosity := 0
	if *verbose1 {
		verbosity = 1
	}
	if *verbose2 {
		verbosity = 2
	}
	if *verbose3 {
		verbosity = 3
	}
	scan.SetVerbosity(verbosity)

	// Provision the render browser up front (when rendering) so any first-run
	// Chromium download happens with a visible notice before scanning begins,
	// rather than silently stalling the first page render.
	if *render && *proxyAddr == "" && len(targets) > 0 {
		scan.WarmBrowser()
	}

	extractor := scan.NewExtractor(*safe, *longSecret)
	extractor.SetSnippet(*snippet)
	if *noSourceMaps {
		extractor.SetRecoverSourceMaps(false)
	}
	if *rulesFile != "" {
		if err := extractor.LoadRulesFile(*rulesFile); err != nil {
			log.Fatal(err)
		}
	}
	if *allowFile != "" {
		if err := extractor.LoadAllowlist(*allowFile); err != nil {
			log.Fatal(err)
		}
	}

	if *proxyAddr != "" {
		var out *os.File = os.Stdout
		if *outFile != "" {
			f, err := os.Create(*outFile)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			out = f
		}
		printer := output.NewPrinter(*format, !*quiet, true, *snippet, version)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := proxy.Run(ctx, *proxyAddr, extractor, printer, out, *endpoints); err != nil {
			log.Fatal(err)
		}
		return
	}

	scanStartedAt := time.Now().UTC()
	var allMatches []scan.Match
	for _, target := range targets {
		var ms []scan.Match
		var err error

		if target == "-" {
			reader := bufio.NewReader(os.Stdin)
			if *posts {
				ms, err = extractor.ScanReaderPostRequests("stdin", reader)
				if err != nil {
					err = fmt.Errorf("failed to scan POST requests from stdin: %w", err)
				}
			} else {
				ms, err = extractor.ScanReaderWithEndpoints("stdin", reader)
				if err != nil {
					err = fmt.Errorf("failed to scan endpoints from stdin: %w", err)
				}
			}
		} else if isURL(target) {
			if *crawl || *full {
				opts := scan.DefaultCrawlOptions()
				opts.MaxDepth = *crawlDepth
				if *crawlAll {
					opts.MaxDepth = -1
				}
				opts.MaxPages = *crawlMaxPages
				opts.Concurrency = *crawlWorkers
				opts.ResumeFile = *crawlResume
				opts.Permute = *crawlPermute || *full
				opts.PermuteMax = *crawlPermuteMax
				if *noMethods {
					opts.ProbeMethods = false
				}
				if *noParamReplay {
					opts.ParamReplay = false
				}
				if *noTemplateDedup {
					opts.TemplateDedup = false
				}
				if *noWellKnown {
					opts.DiscoverWellKnown = false
				}
				opts.DiscoverPassive = *crawlPassive || *full
				opts.PassiveMax = *crawlPassiveMax
				if *crawlPassiveSources != "" {
					opts.PassiveSources = strings.Split(*crawlPassiveSources, ",")
				}
				opts.TemplateSampleMax = *templateSampleMax
				if *methods != "" {
					var ms []string
					for _, m := range strings.Split(*methods, ",") {
						if m = strings.TrimSpace(m); m != "" {
							ms = append(ms, m)
						}
					}
					if len(ms) > 0 {
						opts.RequestMethods = ms
					}
				}
				// The level-0 progress lines are superseded by the richer -v/-vv/-vvv
				// output the scan package emits, so only install them when verbose
				// logging is off (and the banner isn't suppressed).
				if !*quiet && verbosity == 0 {
					opts.Progress = func(pageURL string, depth, pageNum int) {
						fmt.Fprintf(os.Stderr, "[crawl] (%d) depth %d %s\n", pageNum, depth, pageURL)
					}
					opts.OnCalibrated = func(n int) {
						fmt.Fprintf(os.Stderr, "[crawl] auto-calibration learned %d wildcard signature(s)\n", n)
					}
				}
				// A one-line end-of-run summary is useful at every verbosity, so it is
				// gated only on the banner being enabled, not on verbose logging.
				if !*quiet {
					opts.OnComplete = func(s scan.CrawlStats) {
						fmt.Fprintf(os.Stderr,
							"[crawl] done: %d page(s) fetched, %d error(s), %d target(s) discovered, %d enqueued, %d match(es)",
							s.PagesFetched, s.PagesErrored, s.TargetsFound, s.Enqueued, s.Matches)
						if s.PassiveFound > 0 {
							fmt.Fprintf(os.Stderr,
								"; passive %d/%d validated, %d rejected, %d enqueued",
								s.PassiveValidated, s.PassiveFound, s.PassiveRejected, s.PassiveEnqueued)
						}
						if s.PermuteConsidered > 0 {
							fmt.Fprintf(os.Stderr,
								"; permute %d/%d enqueued, %d fetched, %d yielded, %d known + %d admission skipped, %d pruned",
								s.PermuteEnqueued, s.PermuteConsidered, s.PermuteFetched, s.PermuteYielded,
								s.PermuteSkippedKnown, s.PermuteSkippedAdmission, s.PermutePruned)
						}
						fmt.Fprintf(os.Stderr, "; in %s\n", s.Duration.Round(time.Millisecond))
					}
				}
				if *posts {
					ms, err = extractor.ScanURLPostsCrawl(target, *external, *render, opts)
					if err != nil {
						err = fmt.Errorf("failed to crawl POST requests from URL %s: %w", target, err)
					}
				} else {
					ms, err = extractor.ScanURLCrawl(target, *endpoints, *external, *render, opts)
					if err != nil {
						err = fmt.Errorf("failed to crawl endpoints from URL %s: %w", target, err)
					}
				}
			} else if *posts {
				ms, err = extractor.ScanURLPosts(target, *external, *render)
				if err != nil {
					err = fmt.Errorf("failed to scan POST requests from URL %s: %w", target, err)
				}
			} else {
				ms, err = extractor.ScanURL(target, *endpoints, *external, *render)
				if err != nil {
					err = fmt.Errorf("failed to scan endpoints from URL %s: %w", target, err)
				}
			}
		} else {
			f, err2 := os.Open(target)
			if err2 != nil {
				log.Printf("Error: failed to open file %s: %v", target, err2)
				continue
			}
			reader := bufio.NewReader(f)
			if *posts {
				ms, err = extractor.ScanReaderPostRequests(filepath.Base(target), reader)
				if err != nil {
					err = fmt.Errorf("failed to scan POST requests from file %s: %w", target, err)
				}
			} else {
				ms, err = extractor.ScanReaderWithEndpoints(filepath.Base(target), reader)
				if err != nil {
					err = fmt.Errorf("failed to scan endpoints from file %s: %w", target, err)
				}
			}
			f.Close()
		}

		if *posts {
			// A posts crawl harvests HTML markup links (as endpoint_url matches) to
			// follow the link graph; keep only POST endpoints and gathered URLs in the
			// output so those navigation-only links do not leak in.
			ms = scan.FilterPostMatches(ms)
		} else if *endpoints {
			// FilterEndpointMatches keeps only endpoint_* patterns; preserve the
			// crawl's gathered-URL findings, which are endpoint discoveries too.
			gathered := scan.FilterGatheredMatches(ms)
			ms = append(scan.FilterEndpointMatches(ms), gathered...)
		}

		if err != nil {
			log.Printf("Error processing %s: %v", target, err)
			continue
		}
		if len(ms) > 0 {
			allMatches = append(allMatches, ms...)
		}
	}

	allMatches = scan.UniqueMatches(allMatches)

	// Validate the failure threshold up front: an unrecognised value is a
	// configuration failure (exit 2), not a silent no-op.
	if *failOn != "" && scan.SeverityRank(*failOn) == 0 {
		fmt.Fprintf(os.Stderr, "jsminer: invalid -fail-on %q (want info|low|medium|high)\n", *failOn)
		os.Exit(2)
	}

	// Optional DOM vulnerability scan. It is opt-in, applies only to URL targets,
	// and requires rendering. Findings are kept separate from the generic match
	// model so their richer evidence is preserved.
	var domResult scan.DOMScanResult
	ranDOM := false
	if *dom {
		var urlTargets []string
		for _, t := range targets {
			if isURL(t) {
				urlTargets = append(urlTargets, t)
			}
		}
		switch {
		case !*render:
			fmt.Fprintln(os.Stderr, "jsminer: -dom requires rendering; do not pass -render=false")
			os.Exit(2)
		case len(urlTargets) == 0:
			fmt.Fprintln(os.Stderr, "jsminer: -dom needs at least one URL target (DOM scanning works only where browser rendering is available)")
			os.Exit(2)
		}
		cfg, err := buildDOMConfig(*domMode, *domMaxPages, *domMaxProbes, *domWorkers, *domTimeout,
			*domSources, *domSinks, *domMessages, *domAllowExternal, *crawl || *full, *crawlDepth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "jsminer: %v\n", err)
			os.Exit(2)
		}
		if !*quiet {
			cfg.Progress = func(msg string) { fmt.Fprintln(os.Stderr, "jsminer: "+msg) }
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		domResult, err = extractor.ScanDOM(ctx, urlTargets, cfg)
		stop()
		if err != nil {
			fmt.Fprintf(os.Stderr, "jsminer: DOM scan failed: %v\n", err)
			os.Exit(2)
		}
		ranDOM = true
	}

	var out *os.File = os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		out = f
	}

	showSource := *showSourceFlag || len(targets) > 1
	printer := output.NewPrinter(*format, !*quiet, showSource, *snippet, version)

	useReport := ranDOM || *format == "jsonl" || *format == "ndjson"
	if useReport {
		report := output.Report{Matches: allMatches, DOM: domResult.Findings, ScanTime: scanStartedAt}
		if ranDOM {
			summary := domResult.Summary
			report.DOMSummary = &summary
		}
		if err := printer.PrintReport(out, report); err != nil {
			log.Fatal(err)
		}
	} else if err := printer.PrintScan(out, allMatches, scanStartedAt); err != nil {
		log.Fatal(err)
	}

	os.Exit(exitCode(*failOn, allMatches, domResult.Findings))
}

// exitCode maps the findings to the process exit status. With no threshold it
// preserves the historical behaviour (exit 1 on any finding, 0 otherwise). With
// a threshold it exits 1 only when a finding at or above it is present. A
// scanner or configuration failure exits 2 and is handled at the call site
// before this runs.
func exitCode(failOn string, matches []scan.Match, dom []scan.DOMFinding) int {
	if failOn == "" {
		if len(matches) > 0 || len(dom) > 0 {
			return 1
		}
		return 0
	}
	threshold := scan.SeverityRank(failOn)
	for _, m := range matches {
		if scan.SeverityRank(m.Severity) >= threshold {
			return 1
		}
	}
	for _, f := range dom {
		if scan.SeverityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

// buildDOMConfig assembles a DOMScanConfig from the CLI flags, validating the
// mode and the source/sink family lists. It reuses the crawl toggle and depth so
// a DOM scan follows the same in-scope link graph the rest of the scanner does.
func buildDOMConfig(mode string, maxPages, maxProbes, workers, timeout int, sources, sinks string, messages, allowExternal, crawl bool, depth int) (scan.DOMScanConfig, error) {
	cfg := scan.DefaultDOMScanConfig()
	switch mode {
	case scan.DOMModeObserve, scan.DOMModeCanary, scan.DOMModeConfirm:
		cfg.Mode = mode
	default:
		return cfg, fmt.Errorf("invalid -dom-mode %q (want observe|canary|confirm)", mode)
	}
	cfg.MaxPages = maxPages
	cfg.MaxProbes = maxProbes
	cfg.Workers = workers
	if timeout > 0 {
		cfg.PageTimeout = time.Duration(timeout) * time.Second
	}
	cfg.Messages = messages
	cfg.AllowExternal = allowExternal
	cfg.Crawl = crawl
	cfg.MaxDepth = depth

	srcSet, err := parseFamilySet(sources, scan.DOMSourceFamilies(), scan.DOMSourceAliases())
	if err != nil {
		return cfg, fmt.Errorf("-dom-sources: %w", err)
	}
	cfg.Sources = srcSet
	sinkSet, err := parseFamilySet(sinks, scan.DOMSinkFamilies(), nil)
	if err != nil {
		return cfg, fmt.Errorf("-dom-sinks: %w", err)
	}
	cfg.Sinks = sinkSet
	return cfg, nil
}

// parseFamilySet turns a comma-separated family list into an enable-set,
// validating each token against the allowed set (applying aliases first). An
// empty list returns nil, meaning "all families enabled".
func parseFamilySet(list string, allowed []string, aliases map[string][]string) (map[string]bool, error) {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil, nil
	}
	valid := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		valid[a] = true
	}
	set := make(map[string]bool)
	for _, raw := range strings.Split(list, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if expanded, ok := aliases[name]; ok {
			for _, e := range expanded {
				set[e] = true
			}
			continue
		}
		if !valid[name] {
			return nil, fmt.Errorf("unknown family %q", name)
		}
		set[name] = true
	}
	return set, nil
}

func isURL(s string) bool {
	return (len(s) > 7 && s[:7] == "http://") || (len(s) > 8 && s[:8] == "https://")
}
