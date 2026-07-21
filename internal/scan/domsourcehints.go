package scan

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// DOMSourceHint is passive/static intelligence that can be turned into a
// unique DOM canary. ScopeHost keeps hints from separate CLI targets isolated;
// an empty scope lets library callers deliberately apply a hint to every seed.
type DOMSourceHint struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	ScopeHost  string   `json:"scope_host,omitempty"`
	Discovered []string `json:"discovered_by,omitempty"`
}

const (
	DOMHintJavaScriptAccess  = "javascript_access"
	DOMHintJavaScriptURL     = "javascript_url"
	DOMHintJavaScriptRequest = "javascript_request"
	DOMHintPassiveWayback    = "passive_wayback"
	DOMHintPassiveCommon     = "passive_commoncrawl"
	DOMHintDOMForm           = "dom_form"
)

var (
	queryLiteralRe   = regexp.MustCompile(`[?&]([A-Za-z_$][A-Za-z0-9_$@.\-\[\]]{0,127})=`)
	paramCallRe      = regexp.MustCompile("(?i)\\b([A-Za-z_$][A-Za-z0-9_$]*)\\s*\\.\\s*(?:get|getAll|has)\\s*\\(\\s*[\"'`]([A-Za-z_$][A-Za-z0-9_$@.\\-\\[\\]]{0,127})[\"'`]")
	paramVarRe       = regexp.MustCompile(`(?i)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+URLSearchParams\b|[^;\n]{0,120}\buseSearchParams\s*\()`)
	paramArrayRe     = regexp.MustCompile(`(?i)\b(?:const|let|var)\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)[^\]]*\]\s*=\s*\buseSearchParams\s*\(`)
	routerQueryRe    = regexp.MustCompile("(?i)\\b(?:router|route|searchParams|queryParams)\\s*\\.\\s*(?:query\\s*\\.\\s*)?([A-Za-z_$][A-Za-z0-9_$@.\\-]{0,127})")
	routerBracketRe  = regexp.MustCompile("(?i)\\b(?:router|route|searchParams|queryParams)(?:\\s*\\.\\s*query)?\\s*\\[\\s*[\"'`]([A-Za-z_$][A-Za-z0-9_$@.\\-\\[\\]]{0,127})[\"'`]\\s*\\]")
	localStorageRe   = regexp.MustCompile("(?i)\\b(?:window\\s*\\.\\s*)?localStorage\\s*(?:\\.\\s*(?:getItem|setItem|removeItem)\\s*\\(\\s*|\\[\\s*)[\"'`]([^\"'`]{1,128})[\"'`]")
	sessionStorageRe = regexp.MustCompile("(?i)\\b(?:window\\s*\\.\\s*)?sessionStorage\\s*(?:\\.\\s*(?:getItem|setItem|removeItem)\\s*\\(\\s*|\\[\\s*)[\"'`]([^\"'`]{1,128})[\"'`]")
	cookieAccessRe   = regexp.MustCompile("(?i)\\b(?:Cookies|cookieStore)\\s*\\.\\s*(?:get|has)\\s*\\(\\s*[\"'`]([^\"'`]{1,128})[\"'`]")
	objectKeyRe      = regexp.MustCompile("(?:^|[{,]\\s*)(?:[\"']([^\"']{1,128})[\"']|([A-Za-z_$][A-Za-z0-9_$@.\\-]{0,127}))\\s*:")
	jsonBodyObjectRe = regexp.MustCompile(`(?is)\bJSON\s*\.\s*stringify\s*\(\s*\{([^{}]{0,1000})\}\s*\)`)
	formDataKeyRe    = regexp.MustCompile("(?i)\\b(?:formData|body|payload|params)\\s*\\.\\s*(?:append|set)\\s*\\(\\s*[\"'`]([^\"'`]{1,128})[\"'`]")
)

// SetCollectDOMSourceHints enables the hidden intelligence pass used by -dom
// and -full. Keeping it opt-in avoids extra POST-expression parsing for ordinary
// secret-only scans.
func (e *Extractor) SetCollectDOMSourceHints(on bool) {
	e.domHintsMu.Lock()
	defer e.domHintsMu.Unlock()
	e.collectDOMHints = on
	if on && e.domHints == nil {
		e.domHints = make(map[string]DOMSourceHint)
	}
}

// AddDOMSourceHints merges externally discovered hints (currently passive web
// indexes) into the same per-target corpus as JavaScript-derived hints.
func (e *Extractor) AddDOMSourceHints(hints []DOMSourceHint) {
	e.domHintsMu.Lock()
	defer e.domHintsMu.Unlock()
	if !e.collectDOMHints || len(hints) == 0 {
		return
	}
	if e.domHints == nil {
		e.domHints = make(map[string]DOMSourceHint)
	}
	for _, hint := range hints {
		mergeDOMSourceHint(e.domHints, hint)
	}
}

// TakeDOMSourceHints returns the current deterministic corpus and clears it so
// the CLI can associate the hints with exactly one target before scanning the
// next target.
func (e *Extractor) TakeDOMSourceHints() []DOMSourceHint {
	e.domHintsMu.Lock()
	defer e.domHintsMu.Unlock()
	out := make([]DOMSourceHint, 0, len(e.domHints))
	for _, hint := range e.domHints {
		hint.Discovered = uniqueSortedStrings(hint.Discovered)
		out = append(out, hint)
	}
	e.domHints = make(map[string]DOMSourceHint)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (e *Extractor) captureDOMSourceHints(data []byte) {
	e.domHintsMu.Lock()
	on := e.collectDOMHints
	e.domHintsMu.Unlock()
	if !on {
		return
	}
	e.AddDOMSourceHints(discoverDOMSourceHints(data))
}

func mergeDOMSourceHint(dst map[string]DOMSourceHint, hint DOMSourceHint) {
	hint.Kind = strings.TrimSpace(hint.Kind)
	hint.Name = strings.TrimSpace(hint.Name)
	if !validDOMSourceHintName(hint.Name) {
		return
	}
	switch hint.Kind {
	case SourceURLQuery, SourceCookie, SourceLocalStorage, SourceSessionStorage:
	default:
		return
	}
	key := hint.ScopeHost + "\x1f" + hint.Kind + "\x1f" + hint.Name
	if old, ok := dst[key]; ok {
		old.Discovered = append(old.Discovered, hint.Discovered...)
		old.Discovered = uniqueSortedStrings(old.Discovered)
		dst[key] = old
		return
	}
	hint.Discovered = uniqueSortedStrings(hint.Discovered)
	dst[key] = hint
}

func uniqueSortedStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validDOMSourceHintName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("&=#?/%\\\"'`", r) {
			return false
		}
	}
	return true
}

// discoverDOMSourceHints mines source names without emitting them as ordinary
// findings. It combines direct DOM/API access patterns with URLs and request
// bodies, which catches both explicit searchParams.get("q") code and parameters
// that are only present in fetch/axios configuration.
func discoverDOMSourceHints(data []byte) []DOMSourceHint {
	byKey := make(map[string]DOMSourceHint)
	add := func(kind, name, provenance string) {
		mergeDOMSourceHint(byKey, DOMSourceHint{Kind: kind, Name: name, Discovered: []string{provenance}})
	}

	for _, match := range queryLiteralRe.FindAllSubmatch(data, -1) {
		add(SourceURLQuery, string(match[1]), DOMHintJavaScriptURL)
	}

	paramVars := map[string]bool{
		"searchparams": true, "urlsearchparams": true, "queryparams": true,
	}
	for _, re := range []*regexp.Regexp{paramVarRe, paramArrayRe} {
		for _, match := range re.FindAllSubmatch(data, -1) {
			paramVars[strings.ToLower(string(match[1]))] = true
		}
	}
	for _, match := range paramCallRe.FindAllSubmatch(data, -1) {
		receiver := strings.ToLower(string(match[1]))
		if paramVars[receiver] || strings.Contains(receiver, "search") || strings.Contains(receiver, "query") || strings.Contains(receiver, "param") {
			add(SourceURLQuery, string(match[2]), DOMHintJavaScriptAccess)
		}
	}
	for _, re := range []*regexp.Regexp{routerQueryRe, routerBracketRe} {
		for _, match := range re.FindAllSubmatch(data, -1) {
			name := string(match[1])
			if strings.EqualFold(name, "query") || strings.EqualFold(name, "get") || strings.EqualFold(name, "has") {
				continue
			}
			add(SourceURLQuery, name, DOMHintJavaScriptAccess)
		}
	}

	for _, match := range localStorageRe.FindAllSubmatch(data, -1) {
		add(SourceLocalStorage, string(match[1]), DOMHintJavaScriptAccess)
	}
	for _, match := range sessionStorageRe.FindAllSubmatch(data, -1) {
		add(SourceSessionStorage, string(match[1]), DOMHintJavaScriptAccess)
	}
	for _, match := range cookieAccessRe.FindAllSubmatch(data, -1) {
		add(SourceCookie, string(match[1]), DOMHintJavaScriptAccess)
	}
	for _, match := range jsonBodyObjectRe.FindAllSubmatch(data, -1) {
		for _, name := range parameterNamesFromExpression(string(match[1])) {
			add(SourceURLQuery, name, DOMHintJavaScriptRequest)
		}
	}
	for _, match := range formDataKeyRe.FindAllSubmatch(data, -1) {
		add(SourceURLQuery, string(match[1]), DOMHintJavaScriptRequest)
	}

	// parseJSPostRequests already understands fetch, axios, XHR, jQuery and
	// several common wrappers. Reuse it only while the hint pass is enabled.
	for _, request := range parseJSPostRequests(data) {
		for _, name := range queryNamesFromURL(request.Value) {
			add(SourceURLQuery, name, DOMHintJavaScriptURL)
		}
		for _, name := range parameterNamesFromExpression(request.Params) {
			add(SourceURLQuery, name, DOMHintJavaScriptRequest)
		}
	}

	out := make([]DOMSourceHint, 0, len(byKey))
	for _, hint := range byKey {
		out = append(out, hint)
	}
	return out
}

func queryNamesFromURL(raw string) []string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(parsed.Query()))
	for name := range parsed.Query() {
		if validDOMSourceHintName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func parameterNamesFromExpression(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > 16<<10 {
		raw = raw[:16<<10]
	}
	seen := make(map[string]struct{})
	for _, match := range queryLiteralRe.FindAllStringSubmatch("?"+strings.TrimPrefix(raw, "?"), -1) {
		if validDOMSourceHintName(match[1]) {
			seen[match[1]] = struct{}{}
		}
	}
	for _, match := range objectKeyRe.FindAllStringSubmatch(raw, -1) {
		name := match[1]
		if name == "" {
			name = match[2]
		}
		if validDOMSourceHintName(name) {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
