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

func main() {
	format := flag.String("format", "json", "output format: pretty or json")
	safe := flag.Bool("safe", false, "safe mode - only scan JS")
	allowFile := flag.String("allow", "", "allowlist file")
	rulesFile := flag.String("rules", "", "extra regex rules YAML")
	endpoints := flag.Bool("endpoints", false, "only return HTTP endpoints")
	posts := flag.Bool("posts", false, "only return HTTP POST request endpoints")
	external := flag.Bool("external", true, "follow external scripts and imports")
	render := flag.Bool("render", true, "render pages in headless Chrome")
	insecure := flag.Bool("insecure", true, "skip TLS certificate verification")
	longSecret := flag.Bool("longsecret", false, "detect generic long secrets")
	outFile := flag.String("output", "", "output file (stdout default)")
	quiet := flag.Bool("quiet", false, "suppress banner")
	proxyAddr := flag.String("proxy", "", "run as proxy on address (e.g., :8080)")
	crawl := flag.Bool("crawl", false, "crawl in-scope endpoints/paths discovered on each page to reach more JS and secrets")
	crawlDepth := flag.Int("crawl-depth", 2, "max link hops to follow beyond the seed page when -crawl is set")
	crawlMaxPages := flag.Int("crawl-max-pages", 200, "max pages to fetch during a crawl (0 = unlimited)")
	ac := flag.Bool("ac", false, "auto-calibrate crawl: skip catch-all/soft-404 and duplicate pages (requires -crawl)")
	targetsFile := flag.String("targets", "", "file with list of targets")
	pluginsFlag := flag.String("plugins", "", "comma-separated plugin files")
	showSourceFlag := flag.Bool("show-source", false, "show source of each record (auto-enabled for multiple targets)")
	snippet := flag.Bool("snippet", false, "show a JS-prettified, syntax-highlighted code snippet around each finding")
	timeout := flag.Int("timeout", 8, "wait time in seconds for dynamic content to load when rendering pages (default: 8)")
	var headerFlags headerSlice
	flag.Var(&headerFlags, "header", "HTTP header in 'Key: Value' format. May be repeated")
	flag.Parse()

	// handle flags placed after positional arguments
	args := flag.Args()
	leftover := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			leftover = append(leftover, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		parts := strings.SplitN(name, "=", 2)
		name = parts[0]
		switch name {
		case "endpoints":
			*endpoints = true
		case "posts":
			*posts = true
		case "render":
			val := "true"
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if b, err := strconv.ParseBool(val); err == nil {
				*render = b
			} else {
				*render = true
			}
		case "external":
			val := "true"
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if b, err := strconv.ParseBool(val); err == nil {
				*external = b
			} else {
				*external = true
			}
		case "safe":
			*safe = true
		case "longsecret":
			*longSecret = true
		case "quiet":
			*quiet = true
		case "show-source":
			*showSourceFlag = true
		case "snippet":
			*snippet = true
		case "crawl":
			*crawl = true
		case "ac":
			*ac = true
		case "crawl-depth", "crawl-max-pages":
			val := ""
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if n, err := strconv.Atoi(val); err == nil {
				if name == "crawl-depth" {
					*crawlDepth = n
				} else {
					*crawlMaxPages = n
				}
			}
		case "insecure":
			val := "true"
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if b, err := strconv.ParseBool(val); err == nil {
				*insecure = b
			} else {
				*insecure = true
			}
		case "timeout":
			val := ""
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if t, err := strconv.Atoi(val); err == nil {
				*timeout = t
			}
		case "header":
			val := ""
			if len(parts) == 2 {
				val = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
			if val != "" {
				headerFlags = append(headerFlags, val)
			}
		case "format", "allow", "rules", "output", "targets", "plugins":
			if i+1 < len(args) {
				val := args[i+1]
				i++
				switch name {
				case "format":
					*format = val
				case "allow":
					*allowFile = val
				case "rules":
					*rulesFile = val
				case "output":
					*outFile = val
				case "targets":
					*targetsFile = val
				case "plugins":
					*pluginsFlag = val
				}
			}
		default:
			leftover = append(leftover, a)
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
	scan.SetSkipTLSVerification(*insecure)

	if *ac && !*crawl && *proxyAddr == "" && !*quiet {
		fmt.Fprintln(os.Stderr, "note: -ac has no effect without -crawl")
	}

	extractor := scan.NewExtractor(*safe, *longSecret)
	extractor.SetSnippet(*snippet)
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
			if *crawl {
				opts := scan.DefaultCrawlOptions()
				opts.MaxDepth = *crawlDepth
				opts.MaxPages = *crawlMaxPages
				opts.AutoCalibrate = *ac
				if !*quiet {
					opts.Progress = func(pageURL string, depth, pageNum int) {
						fmt.Fprintf(os.Stderr, "[crawl] (%d) depth %d %s\n", pageNum, depth, pageURL)
					}
					if *ac {
						opts.OnCalibrated = func(n int) {
							fmt.Fprintf(os.Stderr, "[crawl] auto-calibration learned %d wildcard signature(s)\n", n)
						}
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

		if !*posts && *endpoints {
			ms = scan.FilterEndpointMatches(ms)
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
	if err := printer.Print(out, allMatches); err != nil {
		log.Fatal(err)
	}

	if len(allMatches) > 0 {
		os.Exit(1)
	}
}

func isURL(s string) bool {
	return (len(s) > 7 && s[:7] == "http://") || (len(s) > 8 && s[:8] == "https://")
}
