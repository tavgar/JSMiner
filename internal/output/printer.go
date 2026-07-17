package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tavgar/JSMiner/internal/scan"
)

// Printer handles output rendering
type Printer struct {
	format        string
	banner        bool
	showSource    bool
	snippet       bool
	version       string
	printedBanner bool
}

type outMatch struct {
	Source   string `json:"source,omitempty"`
	Pattern  string `json:"pattern"`
	Value    string `json:"value"`
	Params   string `json:"params,omitempty"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet,omitempty"`
}

type scanOutput struct {
	Checksum string     `json:"checksum"`
	ScanTime string     `json:"scan_time"`
	Results  []outMatch `json:"results"`
}

// NewPrinter creates a printer
func NewPrinter(format string, banner bool, showSource bool, snippet bool, version string) *Printer {
	return &Printer{format: format, banner: banner, showSource: showSource, snippet: snippet, version: version}
}

// isTerminal reports whether w is an interactive terminal, in which case ANSI
// color escapes are safe to emit. Output redirected to a file or pipe is left
// uncolored.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ResultsChecksum returns a stable SHA-256 checksum for a complete set of scan
// results. Discovery order, source display, and optional snippets are output
// concerns rather than result identity, so they do not affect the checksum.
func ResultsChecksum(matches []scan.Match) string {
	type checksumMatch struct {
		Pattern  string `json:"pattern"`
		Value    string `json:"value"`
		Params   string `json:"params,omitempty"`
		Severity string `json:"severity"`
	}

	canonical := make([]checksumMatch, len(matches))
	for i, m := range matches {
		canonical[i] = checksumMatch{
			Pattern:  m.Pattern,
			Value:    m.Value,
			Params:   m.Params,
			Severity: m.Severity,
		}
	}
	sort.Slice(canonical, func(i, j int) bool {
		a, b := canonical[i], canonical[j]
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		if a.Params != b.Params {
			return a.Params < b.Params
		}
		return a.Severity < b.Severity
	})

	data, err := json.Marshal(canonical)
	if err != nil {
		// checksumMatch contains only strings, so encoding cannot fail.
		panic(fmt.Sprintf("encode checksum input: %v", err))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// Print writes matches to w and records the current time as the scan time.
func (p *Printer) Print(w io.Writer, matches []scan.Match) error {
	return p.PrintScan(w, matches, time.Now())
}

// PrintScan writes matches and run metadata to w. scanTime is the time at which
// the scan began; callers that do not track it can use Print.
func (p *Printer) PrintScan(w io.Writer, matches []scan.Match, scanTime time.Time) error {
	// Structured output must remain a valid JSON document. The decorative banner
	// is therefore only part of pretty output, even when banner display is enabled.
	if p.format == "pretty" && p.banner && !p.printedBanner {
		fmt.Fprintln(w, Banner(p.version))
		p.printedBanner = true
	}

	if scanTime.IsZero() {
		scanTime = time.Now()
	}
	scanTimeText := scanTime.UTC().Format(time.RFC3339Nano)
	checksum := ResultsChecksum(matches)

	// Gathered-URL findings are shown as their own segment beneath the normal
	// JavaScript findings, so split them out while preserving relative order.
	findings, gathered := splitGathered(matches)

	// Rank the findings so High severity leads, then Medium, then Info. The sort
	// is stable, so discovery order is preserved within each severity band. The
	// gathered-URL segment is left in place beneath the findings.
	scan.SortBySeverity(findings)

	if p.format == "pretty" {
		useColor := p.snippet && isTerminal(w)
		for _, m := range findings {
			p.printPretty(w, m, useColor)
		}
		if len(gathered) > 0 {
			fmt.Fprintln(w, "\n=== Gathered URLs ===")
			for _, m := range gathered {
				p.printPretty(w, m, useColor)
			}
		}
		if len(findings)+len(gathered) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "[scan] checksum=%s scan_time=%s\n", checksum, scanTimeText)
		return nil
	}

	// Emit the normal findings first, then the gathered-URL segment, so the JSON
	// array mirrors the pretty layout (gathered URLs beneath the JS findings).
	ordered := make([]scan.Match, 0, len(findings)+len(gathered))
	ordered = append(ordered, findings...)
	ordered = append(ordered, gathered...)

	out := make([]outMatch, 0, len(ordered))
	for _, m := range ordered {
		params := m.Params
		if params != "" {
			if len(params) > scan.MaxParameterDisplayLength {
				params = params[:scan.MaxParameterDisplayLength-3] + "..."
			}
			// Replace newlines with spaces for better display
			params = strings.ReplaceAll(params, "\n", " ")
			params = strings.ReplaceAll(params, "\r", "")
			params = strings.ReplaceAll(params, "\t", " ")
			// Collapse multiple spaces
			for strings.Contains(params, "  ") {
				params = strings.ReplaceAll(params, "  ", " ")
			}
			params = strings.TrimSpace(params)
		}
		om := outMatch{Pattern: m.Pattern, Value: m.Value, Params: params, Severity: m.Severity}
		if p.showSource {
			om.Source = m.Source
		}
		if p.snippet && m.Snippet != "" {
			om.Snippet = BeautifySnippet(m.Snippet)
		}
		out = append(out, om)
	}
	enc := json.NewEncoder(w)
	return enc.Encode(scanOutput{
		Checksum: checksum,
		ScanTime: scanTimeText,
		Results:  out,
	})
}

// printPretty renders a single match in the pretty (human) format, including its
// parameters and, when enabled, a source-code snippet.
func (p *Printer) printPretty(w io.Writer, m scan.Match, useColor bool) {
	if p.showSource {
		fmt.Fprintf(w, "%s: [%s] (%s) %s", m.Source, m.Pattern, m.Severity, m.Value)
	} else {
		fmt.Fprintf(w, "[%s] (%s) %s", m.Pattern, m.Severity, m.Value)
	}
	if m.Params != "" {
		params := m.Params
		if len(params) > scan.MaxParameterDisplayLength {
			params = params[:scan.MaxParameterDisplayLength-3] + "..."
		}
		// Replace newlines with spaces for better display
		params = strings.ReplaceAll(params, "\n", " ")
		params = strings.ReplaceAll(params, "\r", "")
		params = strings.ReplaceAll(params, "\t", " ")
		// Collapse multiple spaces
		for strings.Contains(params, "  ") {
			params = strings.ReplaceAll(params, "  ", " ")
		}
		fmt.Fprintf(w, " params=%s", strings.TrimSpace(params))
	}
	fmt.Fprintln(w)
	if p.snippet && m.Snippet != "" {
		fmt.Fprint(w, RenderSnippet(m.Snippet, m.Value, useColor))
	}
}

// splitGathered partitions matches into normal findings and gathered-URL
// findings, preserving the relative order within each group.
func splitGathered(matches []scan.Match) (findings, gathered []scan.Match) {
	for _, m := range matches {
		if m.Pattern == scan.GatheredURLPattern {
			gathered = append(gathered, m)
		} else {
			findings = append(findings, m)
		}
	}
	return findings, gathered
}
