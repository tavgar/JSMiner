package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/tavgar/JSMiner/internal/scan"
)

// JSONLSchemaVersion documents the streaming (NDJSON) output schema. Consumers
// key off it to detect an incompatible change. It is emitted on the leading
// scan_meta record and on the trailing scan_summary record.
const JSONLSchemaVersion = "jsminer.jsonl.1"

// Stable record types for machine-readable output. Regular (non-DOM) findings
// carry type "match"; DOM findings carry their own scan.DOMType* values.
const (
	recordTypeMeta    = "scan_meta"
	recordTypeMatch   = "match"
	recordTypeSummary = "scan_summary"
)

// Report bundles everything a single scan can emit: the ordinary matches, any
// DOM findings, and the DOM scan summary when a DOM scan ran. It lets the
// output layer render both kinds coherently across pretty, json and jsonl
// without the caller reaching into format internals.
type Report struct {
	Matches           []scan.Match
	DOM               []scan.DOMFinding
	DOMSummary        *scan.DOMScanSummary
	Reflections       []scan.ReflectionFinding
	ReflectionSummary *scan.ReflectionScanSummary
	ScanTime          time.Time
}

// jsonlMatch is one ordinary finding as a streaming record. Field names mirror
// the json format's outMatch, plus a stable type and a deduplication
// fingerprint.
type jsonlMatch struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Value       string `json:"value"`
	Params      string `json:"params,omitempty"`
	Severity    string `json:"severity"`
	Source      string `json:"source,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// matchFingerprint is the deterministic dedup identity of an ordinary finding:
// its pattern, value, params, severity and source, hashed. Transient output
// concerns (snippets, display order) do not enter it.
func matchFingerprint(m scan.Match) string {
	h := sha256.Sum256([]byte(strings.Join([]string{m.Pattern, m.Value, m.Params, m.Severity, m.Source}, "\x1f")))
	return fmt.Sprintf("%x", h[:16])
}

// domFindingFingerprint returns a finding's fingerprint, computing a stable one
// if the scanner did not already set it (it always does after dedup).
func domFindingFingerprint(f scan.DOMFinding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	// Fall back to a hash of the identity-bearing fields.
	parts := []string{f.Type, f.Target, f.PageURL, f.FrameURL, f.Context}
	if f.Source != nil {
		parts = append(parts, f.Source.Kind, f.Source.Name)
	}
	if f.Sink != nil {
		parts = append(parts, f.Sink.Name, strconv.Itoa(f.Sink.Argument))
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return fmt.Sprintf("%x", h[:16])
}

// PrintReport renders a full scan report in the printer's format. It is the
// entry point used whenever DOM findings or the streaming jsonl format are in
// play; the legacy PrintScan remains for ordinary Match-only pretty/json output
// so existing behaviour is byte-for-byte unchanged.
func (p *Printer) PrintReport(w io.Writer, r Report) error {
	switch p.format {
	case "jsonl", "ndjson":
		return p.printJSONL(w, r)
	case "json":
		return p.printJSONReport(w, r)
	default:
		return p.printPrettyReport(w, r)
	}
}

// printJSONL writes the report as newline-delimited JSON: a leading meta record
// carrying the schema version, one record per finding, and a trailing
// scan_summary. Every line is a complete JSON object and nothing else is written
// to the stream, so stdout stays machine-parseable.
func (p *Printer) printJSONL(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	scanTime := r.ScanTime
	if scanTime.IsZero() {
		scanTime = time.Now()
	}

	meta := map[string]any{
		"type":           recordTypeMeta,
		"schema_version": JSONLSchemaVersion,
		"scan_time":      scanTime.UTC().Format(time.RFC3339Nano),
		"checksum":       ResultsChecksum(r.Matches),
	}
	if err := enc.Encode(meta); err != nil {
		return err
	}

	// Ordinary findings first, in severity order, then DOM findings.
	matches := append([]scan.Match(nil), r.Matches...)
	scan.SortBySeverity(matches)
	for _, m := range matches {
		rec := jsonlMatch{
			Type:        recordTypeMatch,
			Pattern:     m.Pattern,
			Value:       m.Value,
			Params:      normalizeParams(m.Params),
			Severity:    m.Severity,
			Fingerprint: matchFingerprint(m),
		}
		if p.showSource {
			rec.Source = m.Source
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}

	dom := append([]scan.DOMFinding(nil), r.DOM...)
	scan.SortDOMFindings(dom)
	for i := range dom {
		if dom[i].Fingerprint == "" {
			dom[i].Fingerprint = domFindingFingerprint(dom[i])
		}
		if err := enc.Encode(dom[i]); err != nil {
			return err
		}
	}

	// Reflection findings carry their own "reflection" type, so each line is a
	// self-describing NDJSON record alongside the match and DOM records.
	refl := append([]scan.ReflectionFinding(nil), r.Reflections...)
	scan.SortReflectionFindings(refl)
	for i := range refl {
		if err := enc.Encode(refl[i]); err != nil {
			return err
		}
	}

	return enc.Encode(p.summaryRecord(r, matches, dom, refl))
}

// summaryRecord builds the trailing scan_summary object, merging DOM scan
// statistics (when a DOM scan ran) with a severity breakdown spanning both
// ordinary and DOM findings.
func (p *Printer) summaryRecord(r Report, matches []scan.Match, dom []scan.DOMFinding, refl []scan.ReflectionFinding) map[string]any {
	bySev := map[string]int{
		scan.SeverityHigh: 0, scan.SeverityMedium: 0, scan.SeverityLow: 0, scan.SeverityInfo: 0,
	}
	for _, m := range matches {
		bySev[strings.ToLower(m.Severity)]++
	}
	for _, f := range dom {
		bySev[strings.ToLower(f.Severity)]++
	}
	for _, f := range refl {
		bySev[strings.ToLower(f.Severity)]++
	}
	rec := map[string]any{
		"type":                 recordTypeSummary,
		"schema_version":       JSONLSchemaVersion,
		"total_findings":       len(matches) + len(dom) + len(refl),
		"match_findings":       len(matches),
		"dom_findings":         len(dom),
		"reflection_findings":  len(refl),
		"findings_by_severity": bySev,
	}
	if r.DOMSummary != nil {
		rec["dom"] = r.DOMSummary
	}
	if r.ReflectionSummary != nil {
		rec["reflection"] = r.ReflectionSummary
	}
	return rec
}

// jsonReport is the json-format document when DOM findings are present. It is a
// superset of the ordinary scanOutput, so ordinary scans keep their exact
// structure while DOM scans gain their richer detail.
type jsonReport struct {
	SchemaVersion     string                      `json:"schema_version"`
	Checksum          string                      `json:"checksum"`
	ScanTime          string                      `json:"scan_time"`
	Results           []outMatch                  `json:"results"`
	DOMFindings       []scan.DOMFinding           `json:"dom_findings,omitempty"`
	DOMSummary        *scan.DOMScanSummary        `json:"dom_summary,omitempty"`
	ReflectionResults []scan.ReflectionFinding    `json:"reflection_findings,omitempty"`
	ReflectionSummary *scan.ReflectionScanSummary `json:"reflection_summary,omitempty"`
}

// printJSONReport renders the json format. With no DOM or reflection findings it
// defers to the legacy PrintScan so ordinary output is byte-for-byte unchanged;
// otherwise it emits the superset document.
func (p *Printer) printJSONReport(w io.Writer, r Report) error {
	if len(r.DOM) == 0 && r.DOMSummary == nil && len(r.Reflections) == 0 && r.ReflectionSummary == nil {
		return p.PrintScan(w, r.Matches, r.ScanTime)
	}

	scanTime := r.ScanTime
	if scanTime.IsZero() {
		scanTime = time.Now()
	}
	matches := append([]scan.Match(nil), r.Matches...)
	scan.SortBySeverity(matches)
	out := make([]outMatch, 0, len(matches))
	for _, m := range matches {
		om := outMatch{Pattern: m.Pattern, Value: m.Value, Params: normalizeParams(m.Params), Severity: m.Severity}
		if p.showSource {
			om.Source = m.Source
		}
		if p.snippet && m.Snippet != "" {
			om.Snippet = BeautifySnippet(m.Snippet)
		}
		out = append(out, om)
	}
	dom := append([]scan.DOMFinding(nil), r.DOM...)
	scan.SortDOMFindings(dom)
	refl := append([]scan.ReflectionFinding(nil), r.Reflections...)
	scan.SortReflectionFindings(refl)

	enc := json.NewEncoder(w)
	return enc.Encode(jsonReport{
		SchemaVersion:     JSONLSchemaVersion,
		Checksum:          ResultsChecksum(r.Matches),
		ScanTime:          scanTime.UTC().Format(time.RFC3339Nano),
		Results:           out,
		DOMFindings:       dom,
		DOMSummary:        r.DOMSummary,
		ReflectionResults: refl,
		ReflectionSummary: r.ReflectionSummary,
	})
}

// printPrettyReport prints the ordinary findings exactly as before and then, if
// any DOM findings exist, a clearly-delimited DOM section and a one-line DOM
// summary. Diagnostics stay off stdout; this is the human format only.
func (p *Printer) printPrettyReport(w io.Writer, r Report) error {
	if err := p.PrintScan(w, r.Matches, r.ScanTime); err != nil {
		return err
	}
	if len(r.DOM) > 0 || r.DOMSummary != nil {
		dom := append([]scan.DOMFinding(nil), r.DOM...)
		scan.SortDOMFindings(dom)
		fmt.Fprintln(w, "\n=== DOM Findings ===")
		for _, f := range dom {
			printDOMFinding(w, f)
		}
		if r.DOMSummary != nil {
			s := r.DOMSummary
			status := "complete"
			if s.TimedOut {
				status = "timed-out"
			} else if s.Partial {
				status = "partial"
			}
			fmt.Fprintf(w, "\n[dom] %s: %d finding(s) across %d page(s), %d probe(s) sent (limit %d); mode=%s\n",
				status, s.Findings, s.PagesScanned, s.ProbesSent, s.ProbesLimit, s.Mode)
			if s.SuppressedMessages > 0 {
				fmt.Fprintf(w, "[dom] %d web-message chatter finding(s) suppressed (no listener and no security-sensitive effect)\n",
					s.SuppressedMessages)
			}
			if s.SourceHints > 0 {
				fmt.Fprintf(w, "[dom] source intelligence: %d hint(s), %d hint probe(s) applied\n",
					s.SourceHints, s.HintProbesSent)
			}
		}
	}
	if len(r.Reflections) > 0 || r.ReflectionSummary != nil {
		printReflectionSection(w, r)
	}
	return nil
}

// printDOMFinding renders one DOM finding in the human format: its severity,
// confidence, source→sink flow, location and key evidence flags.
func printDOMFinding(w io.Writer, f scan.DOMFinding) {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] (%s/%s", f.Type, f.Severity, f.Confidence)
	if f.Confirmed {
		b.WriteString("/confirmed")
	}
	b.WriteString(") ")
	if f.Source != nil {
		b.WriteString(f.Source.Kind)
		if f.Source.Name != "" {
			b.WriteString("[" + f.Source.Name + "]")
		}
		b.WriteString(" -> ")
	}
	if f.Sink != nil {
		fmt.Fprintf(&b, "%s(arg %d)", f.Sink.Name, f.Sink.Argument)
	}
	if f.Message != nil {
		fmt.Fprintf(&b, " listeners=%d origin_checked=%t source_checked=%t reaches_sink=%t",
			f.Message.ListenerCount, f.Message.OriginChecked, f.Message.SourceChecked, f.Message.ReachesSink)
		if f.Message.ListenerCount > 0 {
			fmt.Fprintf(&b, " checks(origin=%d/%d source=%d/%d)",
				f.Message.OriginCheckedListeners, f.Message.ListenerCount,
				f.Message.SourceCheckedListeners, f.Message.ListenerCount)
		}
		if f.Message.ProbeGenerated {
			b.WriteString(" probe_generated=true")
		}
		if f.Message.SentToOrigin != "" {
			fmt.Fprintf(&b, " sent_to=%s", f.Message.SentToOrigin)
		}
		if f.Message.DataShape != "" {
			fmt.Fprintf(&b, " shape=%s", f.Message.DataShape)
		}
	}
	fmt.Fprint(w, b.String())
	fmt.Fprintf(w, "\n    page=%s", f.PageURL)
	if f.FrameURL != "" && f.FrameURL != f.PageURL {
		fmt.Fprintf(w, " frame=%s", f.FrameURL)
	}
	if len(f.Triggers) > 0 {
		fmt.Fprintf(w, " trigger=%s", strings.Join(f.Triggers, "+"))
	} else if f.Trigger != "" {
		fmt.Fprintf(w, " trigger=%s", f.Trigger)
	}
	if f.ValuePreview != "" {
		fmt.Fprintf(w, "\n    value=%s", f.ValuePreview)
	}
	if f.Source != nil && len(f.Source.DiscoveredBy) > 0 {
		fmt.Fprintf(w, "\n    discovered_by=%s", strings.Join(f.Source.DiscoveredBy, ","))
	}
	if f.URL != nil {
		fmt.Fprintf(w, "\n    url=resolved=%t", f.URL.Resolved)
		if f.URL.Scheme != "" {
			fmt.Fprintf(w, " scheme=%s", f.URL.Scheme)
		}
		if f.URL.DestinationOrigin != "" {
			fmt.Fprintf(w, " destination=%s", f.URL.DestinationOrigin)
		}
		if f.URL.Resolved {
			fmt.Fprintf(w, " same_origin=%t", f.URL.SameOrigin)
		}
		if f.URL.CanaryComponent != "" {
			fmt.Fprintf(w, " marker=%s", f.URL.CanaryComponent)
		}
		if f.URL.InputKind != "" {
			fmt.Fprintf(w, " input=%s", f.URL.InputKind)
		}
		if f.URL.ExecutableScheme {
			fmt.Fprint(w, " executable_scheme=true")
		}
	}
	if loc := firstScriptLocation(f.Stack); loc != "" {
		fmt.Fprintf(w, "\n    at=%s", loc)
	}
	if f.Message != nil && len(f.Message.ListenerLocations) > 0 {
		fmt.Fprintf(w, "\n    listener_at=%s", firstScriptLocation(f.Message.ListenerLocations))
		if len(f.Message.ListenerLocations) > 1 {
			fmt.Fprintf(w, " (+%d more)", len(f.Message.ListenerLocations)-1)
		}
	}
	if f.Triage != nil {
		fmt.Fprintf(w, "\n    triage=%s reason=%s", f.Triage.Verdict, f.Triage.Reason)
	}
	if f.Notes != "" {
		fmt.Fprintf(w, "\n    note=%s", f.Notes)
	}
	fmt.Fprintln(w)
}

func firstScriptLocation(stack []scan.DOMStackFrame) string {
	for _, fr := range stack {
		if fr.URL != "" {
			loc := fr.URL + ":" + strconv.Itoa(fr.Line) + ":" + strconv.Itoa(fr.Column)
			if fr.Function != "" {
				return fr.Function + " (" + loc + ")"
			}
			return loc
		}
	}
	return ""
}

// normalizeParams applies the same whitespace normalisation and length bound
// the pretty/json paths already use for a match's params string.
func normalizeParams(params string) string {
	if params == "" {
		return ""
	}
	if len(params) > scan.MaxParameterDisplayLength {
		params = params[:scan.MaxParameterDisplayLength-3] + "..."
	}
	params = strings.ReplaceAll(params, "\n", " ")
	params = strings.ReplaceAll(params, "\r", "")
	params = strings.ReplaceAll(params, "\t", " ")
	for strings.Contains(params, "  ") {
		params = strings.ReplaceAll(params, "  ", " ")
	}
	return strings.TrimSpace(params)
}

// SortReportForTest is a thin, exported helper kept for tests that want stable
// ordering of DOM findings without depending on scan internals.
func SortReportForTest(dom []scan.DOMFinding) { scan.SortDOMFindings(dom) }
