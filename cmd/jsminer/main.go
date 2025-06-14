package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"jsminer/internal/output"
	"jsminer/internal/scan"
)

func main() {
	format := flag.String("format", "json", "output format: pretty or json")
	safe := flag.Bool("safe", true, "safe mode - only scan JS")
	allowFile := flag.String("allow", "", "allowlist file")
	rulesFile := flag.String("rules", "", "extra regex rules YAML")
	endpoints := flag.Bool("endpoints", false, "extract HTTP endpoints from JavaScript")
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
		switch name {
		case "endpoints":
			*endpoints = true
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
		var reader io.ReadCloser
		var base string

		if target == "-" {
			reader = os.Stdin
			base = "stdin"
		} else if isURL(target) {
			rc, err := scan.FetchURL(target)
			if err != nil {
				log.Fatal(err)
			}
			reader = rc
			base = target
		} else {
			f, err := os.Open(target)
			if err != nil {
				log.Fatal(err)
			}
			reader = f
			base = filepath.Base(target)
		}

		input := bufio.NewReader(reader)
		var ms []scan.Match
		var err error
		if *endpoints {
			ms, err = extractor.ScanReaderWithEndpoints(base, input)
		} else {
			ms, err = extractor.ScanReader(base, input)
		}
		if err != nil {
			log.Fatal(err)
		}
		if target != "-" {
			reader.Close()
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
	printer := output.NewPrinter(*format, !*quiet, showSource)
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
