package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

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

// Print writes matches to w
func (p *Printer) Print(w io.Writer, matches []scan.Match) error {
	if p.banner && !p.printedBanner {
		fmt.Fprintln(w, Banner(p.version))
		p.printedBanner = true
	}

	// Gathered-URL findings are shown as their own segment beneath the normal
	// JavaScript findings, so split them out while preserving relative order.
	findings, gathered := splitGathered(matches)

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
		return nil
	}

	type outMatch struct {
		Source   string `json:"source,omitempty"`
		Pattern  string `json:"pattern"`
		Value    string `json:"value"`
		Params   string `json:"params,omitempty"`
		Severity string `json:"severity"`
		Snippet  string `json:"snippet,omitempty"`
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
	return enc.Encode(out)
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
