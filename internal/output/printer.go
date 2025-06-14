package output

import (
	"encoding/json"
	"fmt"
	"io"

	"findsomething/internal/scan"
)

// Printer handles output rendering
type Printer struct {
	format string
	banner bool
}

// NewPrinter creates a printer
func NewPrinter(format string, banner bool) *Printer {
	return &Printer{format: format, banner: banner}
}

// Print writes matches to w
func (p *Printer) Print(w io.Writer, matches []scan.Match) error {
	if p.format == "pretty" {
		for _, m := range matches {
			fmt.Fprintf(w, "%s: [%s] %s\n", m.Source, m.Pattern, m.Value)
		}
		return nil
	}
	enc := json.NewEncoder(w)
	return enc.Encode(matches)
}
