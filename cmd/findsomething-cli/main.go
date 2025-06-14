package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"findsomething/internal/output"
	"findsomething/internal/scan"
)

func main() {
	format := flag.String("format", "json", "output format: pretty or json")
	safe := flag.Bool("safe", true, "safe mode - only scan JS")
	allowFile := flag.String("allow", "", "allowlist file")
	rulesFile := flag.String("rules", "", "extra regex rules YAML")
	outFile := flag.String("output", "", "output file (stdout default)")
	quiet := flag.Bool("quiet", false, "suppress banner")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: findsomething-cli [URL|PATH|-] [flags]")
		os.Exit(2)
	}

	target := flag.Arg(0)
	var input *bufio.Reader
	var base string

	if target == "-" {
		input = bufio.NewReader(os.Stdin)
		base = "stdin"
	} else if isURL(target) {
		rc, err := scan.FetchURL(target)
		if err != nil {
			log.Fatal(err)
		}
		defer rc.Close()
		input = bufio.NewReader(rc)
		base = target
	} else {
		f, err := os.Open(target)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		input = bufio.NewReader(f)
		base = filepath.Base(target)
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

	matches, err := extractor.ScanReader(base, input)
	if err != nil {
		log.Fatal(err)
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

	printer := output.NewPrinter(*format, !*quiet)
	if err := printer.Print(out, matches); err != nil {
		log.Fatal(err)
	}

	if len(matches) > 0 {
		os.Exit(1)
	}
}

func isURL(s string) bool {
	return len(s) > 4 && (s[:7] == "http://" || s[:8] == "https://")
}
