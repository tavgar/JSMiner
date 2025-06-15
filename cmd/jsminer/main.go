package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strconv"
	"strings"

	"github.com/tavgar/JSMiner/internal/output"
	"github.com/tavgar/JSMiner/internal/scan"
)

const version = "0.01v"

func main() {
	format := flag.String("format", "json", "output format: pretty or json")
	safe := flag.Bool("safe", true, "safe mode - only scan JS")
	allowFile := flag.String("allow", "", "allowlist file")
	rulesFile := flag.String("rules", "", "extra regex rules YAML")
	endpoints := flag.Bool("endpoints", false, "extract HTTP endpoints from JavaScript")
	external := flag.Bool("external", true, "follow external scripts and imports")
	outFile := flag.String("output", "", "output file (stdout default)")
	quiet := flag.Bool("quiet", false, "suppress banner")
	targetsFile := flag.String("targets", "", "file with list of targets")
	pluginsFlag := flag.String("plugins", "", "comma-separated plugin files")
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
		case "quiet":
			*quiet = true
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
	if *targetsFile != "" {
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
	targets = append(targets, leftover...)
	if len(targets) == 0 {
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

	extractor := scan.NewExtractor(*safe)
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

	var allMatches []scan.Match
	for _, target := range targets {
		var ms []scan.Match
		var err error

		if target == "-" {
			reader := bufio.NewReader(os.Stdin)
			if *endpoints {
				ms, err = extractor.ScanReaderWithEndpoints("stdin", reader)
			} else {
				ms, err = extractor.ScanReader("stdin", reader)
			}
		} else if isURL(target) {
			ms, err = extractor.ScanURL(target, *endpoints, *external)
		} else {
			f, err2 := os.Open(target)
			if err2 != nil {
				log.Fatal(err2)
			}
			reader := bufio.NewReader(f)
			if *endpoints {
				ms, err = extractor.ScanReaderWithEndpoints(filepath.Base(target), reader)
			} else {
				ms, err = extractor.ScanReader(filepath.Base(target), reader)
			}
			f.Close()
		}

		if err != nil {
			log.Fatal(err)
		}
		if len(ms) > 0 {
			allMatches = append(allMatches, ms...)
		}
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

	showSource := len(targets) > 1
	printer := output.NewPrinter(*format, !*quiet, showSource, version)
	if err := printer.Print(out, allMatches); err != nil {
		log.Fatal(err)
	}

	if len(allMatches) > 0 {
		os.Exit(1)
	}
}

func isURL(s string) bool {
	return len(s) > 4 && (s[:7] == "http://" || s[:8] == "https://")
}
