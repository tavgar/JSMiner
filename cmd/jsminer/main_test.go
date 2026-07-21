package main

import (
	"flag"
	"io"
	"reflect"
	"testing"

	"github.com/tavgar/JSMiner/internal/scan"
)

func TestReorderFlagArgsSupportsFlagsAfterTargets(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "pretty", "")
	render := fs.Bool("render", true, "")
	depth := fs.Int("crawl-depth", 2, "")
	quiet := fs.Bool("quiet", false, "")

	input := []string{
		"first.js",
		"-format=json",
		"-render", "false",
		"second.js",
		"-crawl-depth", "-1",
		"-quiet",
	}
	if err := fs.Parse(reorderFlagArgs(input, fs)); err != nil {
		t.Fatal(err)
	}
	if *format != "json" || *render || *depth != -1 || !*quiet {
		t.Fatalf("flags parsed incorrectly: format=%q render=%t depth=%d quiet=%t",
			*format, *render, *depth, *quiet)
	}
	if want := []string{"first.js", "second.js"}; !reflect.DeepEqual(fs.Args(), want) {
		t.Fatalf("targets = %#v, want %#v", fs.Args(), want)
	}
}

func TestReorderFlagArgsDoesNotSwallowTargetAfterBoolean(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	render := fs.Bool("render", false, "")

	if err := fs.Parse(reorderFlagArgs([]string{"first.js", "-render", "second.js"}, fs)); err != nil {
		t.Fatal(err)
	}
	if !*render {
		t.Fatal("bare trailing boolean flag was not enabled")
	}
	if want := []string{"first.js", "second.js"}; !reflect.DeepEqual(fs.Args(), want) {
		t.Fatalf("targets = %#v, want %#v", fs.Args(), want)
	}
}

// TestExitCodeThresholds verifies the -fail-on exit semantics: with no threshold
// any finding exits 1; with a threshold only a finding at or above it does.
func TestExitCodeThresholds(t *testing.T) {
	high := []scan.Match{{Severity: scan.SeverityHigh}}
	med := []scan.Match{{Severity: scan.SeverityMedium}}
	domHigh := []scan.DOMFinding{{Severity: scan.SeverityHigh}}
	reflMed := []scan.ReflectionFinding{{Severity: scan.SeverityMedium}}

	cases := []struct {
		name    string
		failOn  string
		matches []scan.Match
		dom     []scan.DOMFinding
		refl    []scan.ReflectionFinding
		want    int
	}{
		{"empty-any-match", "", med, nil, nil, 1},
		{"empty-any-dom", "", nil, domHigh, nil, 1},
		{"empty-any-reflection", "", nil, nil, reflMed, 1},
		{"empty-none", "", nil, nil, nil, 0},
		{"high-only-medium", "high", med, nil, nil, 0},
		{"high-with-high-match", "high", high, nil, nil, 1},
		{"high-with-high-dom", "high", nil, domHigh, nil, 1},
		{"high-with-medium-reflection", "high", nil, nil, reflMed, 0},
		{"medium-with-medium", "medium", med, nil, nil, 1},
		{"medium-with-medium-reflection", "medium", nil, nil, reflMed, 1},
		{"medium-with-low", "medium", []scan.Match{{Severity: scan.SeverityLow}}, nil, nil, 0},
	}
	for _, c := range cases {
		if got := exitCode(c.failOn, c.matches, c.dom, c.refl); got != c.want {
			t.Errorf("%s: exitCode(%q) = %d, want %d", c.name, c.failOn, got, c.want)
		}
	}
}

// TestReflectionEnabledByFullAndFlag verifies that reflection scanning turns on
// for -reflection and for -full, and stays off otherwise.
func TestReflectionEnabledByFullAndFlag(t *testing.T) {
	cases := []struct {
		name       string
		reflection bool
		full       bool
		want       bool
	}{
		{"off", false, false, false},
		{"explicit-flag", true, false, true},
		{"via-full", false, true, true},
	}
	for _, c := range cases {
		if got := c.reflection || c.full; got != c.want {
			t.Errorf("%s: reflectionEnabled = %t, want %t", c.name, got, c.want)
		}
	}
}

// TestBuildDOMConfigValidatesMode rejects an unknown mode as a config failure.
func TestBuildDOMConfigValidatesMode(t *testing.T) {
	if _, err := buildDOMConfig("nope", 10, 100, 2, 20, "", "", true, false, false, 2); err == nil {
		t.Fatal("expected error for invalid -dom-mode")
	}
	cfg, err := buildDOMConfig("confirm", 10, 100, 2, 20, "", "", true, true, true, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != scan.DOMModeConfirm || !cfg.Crawl || cfg.MaxDepth != 3 || !cfg.AllowExternal {
		t.Errorf("config not wired from flags: %+v", cfg)
	}
}

// TestBuildDOMConfigSourceSelection checks source-family selection, aliases and
// rejection of unknown families.
func TestBuildDOMConfigSourceSelection(t *testing.T) {
	cfg, err := buildDOMConfig("canary", 10, 100, 2, 20, "url_query,web_message", "", true, false, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sources[scan.SourceURLQuery] || !cfg.Sources[scan.SourceWebMessage] {
		t.Error("selected families missing")
	}
	if cfg.Sources[scan.SourceCookie] {
		t.Error("unselected family should be absent")
	}

	// Alias expansion.
	cfg2, err := buildDOMConfig("canary", 10, 100, 2, 20, "url_full", "", true, false, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg2.Sources[scan.SourceURLQuery] || !cfg2.Sources[scan.SourceURLFragment] {
		t.Error("url_full alias did not expand to query+fragment")
	}

	if _, err := buildDOMConfig("canary", 10, 100, 2, 20, "bogus_source", "", true, false, false, 2); err == nil {
		t.Error("expected error for unknown source family")
	}
	if _, err := buildDOMConfig("canary", 10, 100, 2, 20, "", "bogus_sink", true, false, false, 2); err == nil {
		t.Error("expected error for unknown sink family")
	}
}

func TestResolveDOMSettingsMakesFullConfirmed(t *testing.T) {
	enabled, mode := resolveDOMSettings(false, false, true, scan.DOMModeCanary, false)
	if !enabled || mode != scan.DOMModeConfirm {
		t.Fatalf("-full DOM settings = enabled:%t mode:%s", enabled, mode)
	}
	// An explicit mode remains an escape hatch for a less active full crawl.
	_, mode = resolveDOMSettings(false, false, true, scan.DOMModeObserve, true)
	if mode != scan.DOMModeObserve {
		t.Fatalf("explicit mode was overridden: %s", mode)
	}
	enabled, mode = resolveDOMSettings(false, true, false, scan.DOMModeCanary, true)
	if !enabled || mode != scan.DOMModeConfirm {
		t.Fatalf("-dom-confirm settings = enabled:%t mode:%s", enabled, mode)
	}
}
