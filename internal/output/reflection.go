package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/tavgar/JSMiner/internal/scan"
)

// printReflectionSection renders the human-readable reflection findings block: a
// delimited section of findings followed by a one-line scan summary. It mirrors
// the DOM section so the two param-driven scans read consistently.
func printReflectionSection(w io.Writer, r Report) {
	refl := append([]scan.ReflectionFinding(nil), r.Reflections...)
	scan.SortReflectionFindings(refl)
	fmt.Fprintln(w, "\n=== Reflection Findings ===")
	for _, f := range refl {
		printReflectionFinding(w, f)
	}
	if r.ReflectionSummary != nil {
		s := r.ReflectionSummary
		status := "complete"
		if s.Partial {
			status = "partial"
		}
		fmt.Fprintf(w, "\n[reflection] %s: %d finding(s) across %d url(s), %d probe(s) sent (limit %d), %d param(s) tested\n",
			status, s.Findings, s.URLsScanned, s.ProbesSent, s.ProbesLimit, s.ParamsTested)
	}
}

// printReflectionFinding renders one reflection finding: its severity, confidence,
// the reflected parameter and context, and the key evidence.
func printReflectionFinding(w io.Writer, f scan.ReflectionFinding) {
	fmt.Fprintf(w, "[%s] (%s/%s) %s[%s] -> %s\n",
		f.Type, f.Severity, f.Confidence, f.Method, f.Parameter, f.Context)
	fmt.Fprintf(w, "    url=%s", f.PageURL)
	if f.Occurrences > 0 {
		fmt.Fprintf(w, " occurrences=%d", f.Occurrences)
	}
	if len(f.Unfiltered) > 0 {
		fmt.Fprintf(w, "\n    unfiltered=%s", strings.Join(f.Unfiltered, " "))
	}
	if f.ValuePreview != "" {
		fmt.Fprintf(w, "\n    value=%s", f.ValuePreview)
	}
	if len(f.DiscoveredBy) > 0 {
		fmt.Fprintf(w, "\n    discovered_by=%s", strings.Join(f.DiscoveredBy, ","))
	}
	if f.Triage != nil {
		fmt.Fprintf(w, "\n    triage=%s reason=%s", f.Triage.Verdict, f.Triage.Reason)
	}
	if f.Notes != "" {
		fmt.Fprintf(w, "\n    note=%s", f.Notes)
	}
	fmt.Fprintln(w)
}
