package scan

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// DOMSchemaVersion identifies the DOM finding output schema. It is emitted in
// structured output so downstream consumers can detect an incompatible change.
// Bump the minor version when adding fields, the major version when changing or
// removing an existing field's meaning.
const DOMSchemaVersion = "dom.1.0"

// DOM finding types. These strings are stable public identifiers: automated
// triage keys off them, so their spellings must not change. New analyses
// (client-side prototype pollution, DOM clobbering) are added as new type
// constants rather than by overloading an existing one.
const (
	// DOMTypeFlow is an observed source-to-sink flow: an attacker-controllable
	// input reached a security-sensitive browser sink.
	DOMTypeFlow = "dom_flow"

	// DOMTypeSink is a dangerous sink observed executing without any evidence of
	// controllable input reaching it (observe mode). It is intelligence, not a
	// vulnerability.
	DOMTypeSink = "dom_sink"

	// DOMTypeWebMessage reports postMessage listener/message analysis: what the
	// page listens for, whether it inspects origin/source, and whether message
	// data reached a sink.
	DOMTypeWebMessage = "web_message"

	// DOMTypeSummary is the final scan-summary record emitted once per scan in
	// streaming output.
	DOMTypeSummary = "scan_summary"
)

// Confidence reflects the quality of the evidence behind a DOM finding, kept
// deliberately separate from severity (which reflects impact). A high-severity
// sink reached only by a weak static signal is high severity, low confidence.
const (
	// ConfidenceLow is a static or incomplete indication.
	ConfidenceLow = "low"
	// ConfidenceMedium is a runtime sink observation with uncertain source control.
	ConfidenceMedium = "medium"
	// ConfidenceHigh is a unique canary correlated from a specific source to a
	// specific sink.
	ConfidenceHigh = "high"
	// ConfidenceCertain is controlled execution confirmed.
	ConfidenceCertain = "certain"
)

// DOM trigger categories describe when a flow was observed. They are used both
// as evidence in the finding and, folded to a category, as part of dedup so the
// same flow reached several ways collapses to one record with combined triggers.
const (
	TriggerPageLoad    = "page_load"
	TriggerInteraction = "interaction"
	TriggerPostMessage = "post_message"
)

// Scan phase distinguishes a flow seen during the initial page load from one
// that only appears after the scanner explores further application state.
const (
	PhaseInitialLoad      = "initial_load"
	PhaseStateExploration = "state_exploration"
)

// DOMStackFrame is one frame of a captured JavaScript call stack, locating the
// code that drove data into a sink.
type DOMStackFrame struct {
	Function string `json:"function,omitempty"`
	URL      string `json:"url,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// DOMSource identifies the attacker-controllable input family (kind) and the
// specific input (name, e.g. a query parameter name or cookie name) a flow
// originated from.
type DOMSource struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

// DOMSink identifies the security-sensitive browser API a flow reached and
// which argument carried the controllable data.
type DOMSink struct {
	Name     string `json:"name"`
	Argument int    `json:"argument"`
}

// DOMMessageInfo carries postMessage-specific evidence.
type DOMMessageInfo struct {
	// ListenerCount is how many message listeners were observed on the frame.
	ListenerCount int `json:"listener_count,omitempty"`

	// OriginChecked reports whether a listener's source appears to inspect
	// event.origin. This is evidence the listener looks at origin, NOT proof that
	// origin validation is correct or that it was bypassed.
	OriginChecked bool `json:"origin_checked"`

	// SourceChecked reports whether a listener's source appears to inspect
	// event.source. As with OriginChecked, this is evidence, not proof.
	SourceChecked bool `json:"source_checked"`

	// DataShape is the expected message-data shape when determinable (the property
	// names a listener reads off event.data), e.g. "{cmd, payload}".
	DataShape string `json:"data_shape,omitempty"`

	// ReachesSink reports whether message data was observed reaching a dangerous
	// sink.
	ReachesSink bool `json:"reaches_sink"`

	// SentToOrigin, when set, records that the page sent URL-derived data to a
	// different origin via postMessage — a potential cross-origin data leak.
	SentToOrigin string `json:"sent_to_origin,omitempty"`

	// Identity is a stable grouping key for duplicate messages (origin + shape),
	// so a page that emits the same message repeatedly is reported once.
	Identity string `json:"identity,omitempty"`
}

// DOMFinding is the richer, DOM-specific evidence model. It is intentionally not
// compressed into the generic Match.Params string so automated triage has every
// field it needs. Unset optional fields are omitted from output.
type DOMFinding struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	PageURL string `json:"page_url"`

	FrameURL  string `json:"frame_url,omitempty"`
	FramePath string `json:"frame_path,omitempty"`

	Source *DOMSource `json:"source,omitempty"`
	Sink   *DOMSink   `json:"sink,omitempty"`

	ProbeID string `json:"probe_id,omitempty"`

	// ValuePreview is a bounded, redaction-safe excerpt of the value seen at the
	// sink. It never contains full secrets, cookies, storage values or message
	// contents.
	ValuePreview string `json:"value_preview,omitempty"`

	// Context classifies the sink's parse context: html, js, url or attribute.
	Context string `json:"context,omitempty"`

	Stack []DOMStackFrame `json:"stack,omitempty"`

	// Trigger is the primary trigger category (page_load, interaction,
	// post_message). Triggers holds every distinct trigger a deduplicated flow was
	// observed through.
	Trigger  string   `json:"trigger,omitempty"`
	Triggers []string `json:"triggers,omitempty"`

	// Interaction describes the specific interaction that drove the flow (e.g. a
	// form submission or a clicked control), when applicable.
	Interaction string `json:"interaction,omitempty"`

	// Transform records an observed source transformation or sanitization between
	// source and sink (e.g. "url_decoded", "html_encoded").
	Transform string `json:"transform,omitempty"`

	// Phase records whether the flow occurred during initial loading or later
	// state exploration.
	Phase string `json:"phase,omitempty"`

	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Confirmed  bool   `json:"confirmed"`

	// Message carries postMessage-specific evidence for web_message findings.
	Message *DOMMessageInfo `json:"message,omitempty"`

	// Fingerprint is a deterministic dedup identity derived only from stable
	// properties (never from random canaries, timestamps or transient ids).
	Fingerprint string `json:"fingerprint,omitempty"`

	// Notes carries any diagnostic annotations (e.g. that instrumentation appeared
	// to break page execution). It is advisory context, not part of identity.
	Notes string `json:"notes,omitempty"`
}

// originOf returns scheme://host for a URL, the stable "target origin" component
// of a finding's identity. A malformed URL falls back to itself.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// routeOf returns the path of a URL — the "page route" component of identity.
// Query and fragment are excluded so /search?q=a and /search?q=b share a route.
func routeOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// scriptLocation returns a stable "relevant script location" string from the
// first stack frame carrying a URL. Line and column are included because they
// are stable for a fixed page and distinguish two flows through the same file.
func (f *DOMFinding) scriptLocation() string {
	for _, fr := range f.Stack {
		if fr.URL != "" {
			return fr.URL + ":" + strconv.Itoa(fr.Line) + ":" + strconv.Itoa(fr.Column)
		}
	}
	return ""
}

// computeFingerprint derives a deterministic identity from stable properties
// only: type, target origin, page route, frame, source kind+name, sink name and
// argument, sink context, and the relevant script location. The specific trigger
// is deliberately excluded so the same flow reached through several triggers or
// interactions collapses to one finding (its triggers are then combined). Random
// canary values, timestamps and transient browser identifiers never enter it.
func (f *DOMFinding) computeFingerprint() string {
	var b strings.Builder
	write := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
			b.WriteByte('\x1f') // unit separator keeps fields unambiguous
		}
	}
	write(f.Type, originOf(f.Target), routeOf(f.PageURL), f.FrameURL)
	if f.Source != nil {
		write("src", f.Source.Kind, f.Source.Name)
	}
	if f.Sink != nil {
		write("sink", f.Sink.Name, strconv.Itoa(f.Sink.Argument))
	}
	write("ctx", f.Context, "loc", f.scriptLocation())
	if f.Message != nil {
		write("msg", f.Message.Identity)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum[:16])
}

// severityAtLeast reports whether sev ranks at or above threshold. Both are
// severity labels (high/medium/low/info); an empty threshold means "info".
func severityAtLeast(sev, threshold string) bool {
	if threshold == "" {
		threshold = SeverityInfo
	}
	return severityRank(sev) >= severityRank(threshold)
}

// confidenceRank orders confidence labels for merging; higher is stronger.
func confidenceRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case ConfidenceCertain:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// DedupDOMFindings collapses findings that share a fingerprint into a single
// record, combining their trigger evidence and keeping the strongest severity,
// confidence and confirmation. The result is deterministically ordered
// (severity desc, then fingerprint asc) so identical scans emit identical
// output. Each returned finding carries its computed fingerprint.
func DedupDOMFindings(findings []DOMFinding) []DOMFinding {
	type entry struct {
		f     DOMFinding
		order int
	}
	byFP := make(map[string]*entry)
	var order int
	for i := range findings {
		f := findings[i]
		fp := f.computeFingerprint()
		f.Fingerprint = fp

		primaryTrigger := f.Trigger
		e, ok := byFP[fp]
		if !ok {
			if primaryTrigger != "" {
				f.Triggers = mergeTriggers(f.Triggers, primaryTrigger)
			}
			byFP[fp] = &entry{f: f, order: order}
			order++
			continue
		}

		// Merge into the existing record: union triggers, keep the strongest
		// severity/confidence, and preserve confirmation once observed.
		e.f.Triggers = mergeTriggers(e.f.Triggers, primaryTrigger)
		e.f.Triggers = mergeTriggers(e.f.Triggers, f.Triggers...)
		if severityRank(f.Severity) > severityRank(e.f.Severity) {
			e.f.Severity = f.Severity
		}
		if confidenceRank(f.Confidence) > confidenceRank(e.f.Confidence) {
			e.f.Confidence = f.Confidence
		}
		if f.Confirmed {
			e.f.Confirmed = true
		}
		// Prefer a non-empty preview/stack/interaction if the kept record lacks one.
		if e.f.ValuePreview == "" {
			e.f.ValuePreview = f.ValuePreview
		}
		if len(e.f.Stack) == 0 {
			e.f.Stack = f.Stack
		}
		if e.f.Interaction == "" {
			e.f.Interaction = f.Interaction
		}
		if e.f.Transform == "" {
			e.f.Transform = f.Transform
		}
		if e.f.Message == nil {
			e.f.Message = f.Message
		}
	}

	out := make([]DOMFinding, 0, len(byFP))
	for _, e := range byFP {
		// The primary Trigger becomes the highest-priority category present so the
		// single-valued field is stable regardless of discovery order.
		e.f.Trigger = primaryTriggerOf(e.f.Triggers)
		out = append(out, e.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// mergeTriggers appends any new trigger labels to acc, keeping them sorted and
// unique so the combined evidence is deterministic.
func mergeTriggers(acc []string, add ...string) []string {
	set := make(map[string]struct{}, len(acc)+len(add))
	for _, t := range acc {
		if t != "" {
			set[t] = struct{}{}
		}
	}
	for _, t := range add {
		if t != "" {
			set[t] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// primaryTriggerOf picks the most specific trigger category present, preferring
// an active interaction/post-message over a passive page load.
func primaryTriggerOf(triggers []string) string {
	has := func(t string) bool {
		for _, x := range triggers {
			if x == t {
				return true
			}
		}
		return false
	}
	switch {
	case has(TriggerPostMessage):
		return TriggerPostMessage
	case has(TriggerInteraction):
		return TriggerInteraction
	case has(TriggerPageLoad):
		return TriggerPageLoad
	case len(triggers) > 0:
		return triggers[0]
	default:
		return ""
	}
}

// SortDOMFindings orders findings by severity (desc) then fingerprint (asc),
// matching DedupDOMFindings' ordering so any list can be presented consistently.
func SortDOMFindings(findings []DOMFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}
