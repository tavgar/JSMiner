package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/tavgar/JSMiner/internal/scan"
)

// Printer handles output rendering
type Printer struct {
	format     string
	banner     bool
	showSource bool
	version    string
}

// NewPrinter creates a printer
func NewPrinter(format string, banner bool, showSource bool, version string) *Printer {
	return &Printer{format: format, banner: banner, showSource: showSource, version: version}
}

// Print writes matches to w
func (p *Printer) Print(w io.Writer, matches []scan.Match) error {
	if p.banner {
		fmt.Fprintln(w, Banner(p.version))
	}

	if p.format == "pretty" {
		for _, m := range matches {
			if p.showSource {
				fmt.Fprintf(w, "%s: [%s] (%s) %s\n", m.Source, m.Pattern, m.Severity, m.Value)
			} else {
				fmt.Fprintf(w, "[%s] (%s) %s\n", m.Pattern, m.Severity, m.Value)
			}
		}
		return nil
	}

	type outMatch struct {
		Source   string `json:"source,omitempty"`
		Pattern  string `json:"pattern"`
		Value    string `json:"value"`
		Severity string `json:"severity"`
	}
	out := make([]outMatch, 0, len(matches))
	for _, m := range matches {
		om := outMatch{Pattern: m.Pattern, Value: m.Value, Severity: m.Severity}
		if p.showSource {
			om.Source = m.Source
		}
		out = append(out, om)
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}
