package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/tavgar/JSMiner/internal/scan/jsast"
)

// Match represents a single regex hit
type Match struct {
	Source   string `json:"source"`
	Pattern  string `json:"pattern"`
	Value    string `json:"value"`
	Params   string `json:"params,omitempty"`
	Severity string `json:"severity"`

	// Snippet holds a raw source window surrounding the matched value. It is
	// only populated when snippet capture is enabled (see SetSnippet) and is
	// consumed by the output layer to render a prettified, highlighted code
	// excerpt. It is intentionally excluded from the default JSON encoding.
	Snippet string `json:"-"`
}

// Extractor holds compiled regex patterns
type Extractor struct {
	rules             []Rule
	safeMode          bool
	allowlist         []string
	jsRules           map[string]bool
	snippet           bool
	calibrator        *autoCalibrator
	recoverSourceMaps bool
}

// SetRecoverSourceMaps toggles recovery of original source from JavaScript
// source maps. When on (the default), a scanned JS bundle that advertises a
// source map has its original, pre-bundled sources recovered and scanned so
// their secrets and endpoints surface as ordinary matches. Disabling it skips
// all source-map fetching and decoding.
func (e *Extractor) SetRecoverSourceMaps(on bool) { e.recoverSourceMaps = on }

// SetCalibrator installs (or clears, when nil) an auto-calibrator used during
// crawls to skip catch-all/soft-404 and duplicate pages. It is nil by default,
// leaving non-crawl scans unaffected.
func (e *Extractor) SetCalibrator(c *autoCalibrator) { e.calibrator = c }

// SetSnippet toggles capture of a raw source window around each match so the
// output layer can render a code excerpt. It is disabled by default because
// locating every value in the source adds work proportional to the input size.
func (e *Extractor) SetSnippet(on bool) { e.snippet = on }

// parseSimpleYAML is a very small YAML parser that supports the subset used in
// the tests: a mapping of string keys to string values. It ignores blank lines
// and comments starting with '#'. The function returns an error if the input
// does not conform to the expected "key: value" format.
func parseSimpleYAML(data []byte) (map[string]string, error) {
	out := make(map[string]string)
	lines := bytes.Split(data, []byte("\n"))
	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		parts := bytes.SplitN(l, []byte(":"), 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %s", l)
		}
		key := strings.TrimSpace(string(parts[0]))
		val := strings.TrimSpace(string(parts[1]))
		if key == "" || val == "" {
			return nil, fmt.Errorf("invalid line: %s", l)
		}
		val = strings.Trim(val, "'\"")
		out[key] = val
	}
	return out, nil
}

var jsExts = []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".wasm"}

var baseJSRules = map[string]bool{
	"jwt":        true,
	"google_api": true,
	// Headers are set from JS (fetch/axios/XHR), so the rule is JS-relevant.
	"http_header": true,
	// Provider token formats are JS-relevant secrets and run in safe mode too.
	"github_token": true,
	"github_pat":   true,
	"stripe_key":   true,
	"slack_token":  true,
	"gitlab_pat":   true,
	"npm_token":    true,
	"sendgrid_key": true,
	"google_oauth": true,
	"aws_akia":     true,
	// AI provider keys leak from browser-side model calls, so they are JS-relevant.
	"anthropic_key":     true,
	"openai_key":        true,
	"openai_legacy":     true,
	"openrouter_key":    true,
	"groq_key":          true,
	"xai_key":           true,
	"perplexity_key":    true,
	"huggingface_token": true,
	"replicate_key":     true,
	"langsmith_key":     true,
}

// default patterns (simplified)
var defaultPatterns = map[string]string{
	"email":      `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"jwt":        `eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`,
	"aws_secret": `(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}`,
	"google_api": `AIza[0-9A-Za-z-_]{35}`,
	"bearer":     `(?i)bearer\s+[A-Za-z0-9._-]{10,}`,
	// generic API key style values
	"api_key": `(?i)api[-_]?key\s*[:=]\s*["']?[A-Za-z0-9-_]{16,}`,
	// generic access or auth token values
	"token": `(?i)(?:access|auth)?_?token\s*[:=]\s*["']?[A-Za-z0-9-_]{10,}`,
	// passwords with at least 4 non-space characters
	"password": `(?i)password\s*[:=]\s*["']?\S{4,}`,
	// long alphanumeric strings that might be secrets. Allow common
	// prefixes like "key" or "secret" for additional context.
	"long_secret": `(?:(?i)(?:key|secret|token|api)[_-]?[:=]\s*)?[A-Za-z0-9_-]{32,}`,

	// Provider token formats, matched by their distinctive value rather than the
	// surrounding keyword. Minifiers mangle the assigning variable name and strip
	// comments, so keyword-based rules (`github_token = ...`) silently stop firing
	// on production bundles; these prefix+charset+length signatures still match,
	// and are specific enough to add negligible false positives.
	"github_token": `\bgh[pousr]_[A-Za-z0-9]{36}\b`,
	"github_pat":   `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`,
	"stripe_key":   `\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,99}\b`,
	"slack_token":  `\bxox[baprs]-[A-Za-z0-9-]{10,}`,
	"gitlab_pat":   `\bglpat-[A-Za-z0-9_-]{20}\b`,
	"npm_token":    `\bnpm_[A-Za-z0-9]{36}\b`,
	"sendgrid_key": `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
	"google_oauth": `\bya29\.[A-Za-z0-9_-]{20,}`,
	"aws_akia":     `\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`,

	// AI provider keys. LLM credentials are routinely hard-coded into front-end
	// bundles (a "call the model straight from the browser" prototype that ships),
	// so they are worth matching on their own signature like the rules above.
	// Each prefix is vendor-assigned and long enough that a hit is not accidental.
	"anthropic_key":     `\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,120}\b`,
	"openai_key":        `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b`,
	"openai_legacy":     `\bsk-[A-Za-z0-9]{48}\b`,
	"openrouter_key":    `\bsk-or-v1-[a-f0-9]{64}\b`,
	"groq_key":          `\bgsk_[A-Za-z0-9]{52}\b`,
	"xai_key":           `\bxai-[A-Za-z0-9]{80}\b`,
	"perplexity_key":    `\bpplx-[A-Za-z0-9]{32,}\b`,
	"huggingface_token": `\bhf_[A-Za-z0-9]{34,}\b`,
	"replicate_key":     `\br8_[A-Za-z0-9]{37}\b`,
	"langsmith_key":     `\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b`,
}

// defaultSeverities ranks the default rules. Distinctive provider/cloud
// credential formats are High (a match is almost certainly a live secret);
// generic keyword-anchored credentials are Medium (probable secrets that
// warrant review); everything else — emails, generic high-entropy strings — is
// Info. Any default rule not listed here falls back to Info via severityFor.
var defaultSeverities = map[string]string{
	"jwt":          SeverityHigh,
	"aws_secret":   SeverityHigh,
	"google_api":   SeverityHigh,
	"github_token": SeverityHigh,
	"github_pat":   SeverityHigh,
	"stripe_key":   SeverityHigh,
	"slack_token":  SeverityHigh,
	"gitlab_pat":   SeverityHigh,
	"npm_token":    SeverityHigh,
	"sendgrid_key": SeverityHigh,
	"google_oauth": SeverityHigh,
	"aws_akia":     SeverityHigh,

	"anthropic_key":     SeverityHigh,
	"openai_key":        SeverityHigh,
	"openai_legacy":     SeverityHigh,
	"openrouter_key":    SeverityHigh,
	"groq_key":          SeverityHigh,
	"xai_key":           SeverityHigh,
	"perplexity_key":    SeverityHigh,
	"huggingface_token": SeverityHigh,
	"replicate_key":     SeverityHigh,
	"langsmith_key":     SeverityHigh,

	"bearer":   SeverityMedium,
	"api_key":  SeverityMedium,
	"token":    SeverityMedium,
	"password": SeverityMedium,

	"email":       SeverityInfo,
	"long_secret": SeverityInfo,
}

// severityFor returns the configured severity for a default rule name, or Info
// when the rule is unranked.
func severityFor(name string) string {
	if s, ok := defaultSeverities[name]; ok {
		return s
	}
	return SeverityInfo
}

// defaultFilters attaches a post-match validation to specific default rules to
// suppress the false positives they generate on minified/bundled JavaScript.
// (ipv4 is handled by the dedicated, context-aware ipv4Rule instead.)
var defaultFilters = map[string]func(string) bool{
	"api_key":  credentialValueFilter,
	"token":    credentialValueFilter,
	"password": credentialValueFilter,
}

// powerPatterns provide additional regexes enabled by default.
var powerPatterns = map[string]string{
	"phone": `\d{3}-\d{3}-\d{4}`,
	// Require at least two colons so bare "a:b" object literals are ignored;
	// validIPv6Match then enforces a parseable, multi-group address.
	"ipv6": `(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F]*`,
	// crude file path detection for Unix and Windows paths. Requires a
	// leading whitespace or start of line to avoid matching fragments in
	// secrets.
	"path": `(?:^|\s)(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)|[A-Za-z]:\\\\(?:[^\\\\\s]+\\\\)*[^\\\\\s]+`,
}

// powerFilters attaches a post-match validation to specific power rules.
var powerFilters = map[string]func(string) bool{
	"ipv6": validIPv6Match,
	"path": validPathMatch,
}

// powerContextFilters attaches a context-aware validation (one that inspects the
// bytes around a hit) to specific power rules. `path` uses it to reject regex
// literals whose trailing metacharacter sits just past the match.
var powerContextFilters = map[string]func(data []byte, start, end int) bool{
	"path": pathNotRegexLiteral,
}

// NewExtractor creates an Extractor
func NewExtractor(safe bool, longSecret bool) *Extractor {
	e := &Extractor{safeMode: safe, jsRules: make(map[string]bool), recoverSourceMaps: true}
	for k, v := range baseJSRules {
		e.jsRules[k] = v
	}
	for name, pat := range defaultPatterns {
		if name == "long_secret" && !longSecret {
			continue
		}
		r := newRegexRule(name, pat, severityFor(name))
		if f, ok := defaultFilters[name]; ok {
			r.Filter = f
		}
		e.rules = append(e.rules, r)
		if name == "long_secret" {
			e.jsRules[name] = true
		}
	}
	for name, pat := range powerPatterns {
		r := newRegexRule(name, pat, "info")
		if f, ok := powerFilters[name]; ok {
			r.Filter = f
		}
		if cf, ok := powerContextFilters[name]; ok {
			r.ContextFilter = cf
		}
		e.rules = append(e.rules, r)
	}
	// ipv4 uses a dedicated context-aware rule to reject SVG/coordinate streams.
	e.rules = append(e.rules, newIPv4Rule())
	// http_header likewise needs context to tell a header map from the object
	// literals and CSS declarations that share the `name: value` shape.
	e.rules = append(e.rules, newHTTPHeaderRule())
	e.rules = append(e.rules, getRegisteredRules()...)
	return e
}

// LoadRulesFile loads additional regex patterns from a YAML file
func (e *Extractor) LoadRulesFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	rules, err := parseSimpleYAML(data)
	if err != nil {
		return err
	}

	for name, pat := range rules {
		r, err := regexp.Compile(pat)
		if err != nil {
			return err
		}
		e.rules = append(e.rules, RegexRule{Name: strings.TrimSpace(name), RE: r, Severity: "info"})
	}
	return nil
}

// LoadAllowlist loads allowed domain suffixes
func (e *Extractor) LoadAllowlist(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		e.allowlist = append(e.allowlist, line)
	}
	return sc.Err()
}

func isJSFile(source string) bool {
	// URL query strings and fragments are not part of the filename. Without
	// stripping them, /app.js?v=123 is seen as having extension ".js?v=123" and
	// safe mode silently skips a perfectly ordinary cache-busted bundle.
	if u, err := url.Parse(source); err == nil && u.Path != "" &&
		(u.Scheme != "" || u.RawQuery != "" || u.Fragment != "") {
		source = u.Path
	}
	ext := strings.ToLower(filepath.Ext(source))
	for _, e := range jsExts {
		if ext == e {
			return true
		}
	}
	return false
}

// looksLikeJSON reports whether data appears to be a JSON document — its first
// non-whitespace byte is `{` or `[`. Crawled API responses are frequently JSON
// served under an extensionless URL (no .js/.json in the path), so endpoint
// extraction keys on the content here, not only the filename. That is what lets a
// crawl follow the hypermedia links an API body carries — href/self/next and the
// nested targets of JSON:API `links` or HAL `_links` — to reach paginated and
// related resources nothing in the HTML or JS references. The links surface as
// ordinary quoted URL/path strings, which the endpoint patterns already capture.
func looksLikeJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

func (e *Extractor) isJSRule(name string) bool {
	return e.jsRules[name]
}

func (e *Extractor) isAllowed(source string) bool {
	for _, s := range e.allowlist {
		if strings.HasSuffix(source, s) {
			return true
		}
	}
	return false
}

// ScanReader scans an io.Reader and returns matches
func (e *Extractor) ScanReader(source string, r io.Reader) ([]Match, error) {
	return e.scanReader(source, r, source == "stdin" || isJSFile(source))
}

// scanReader is ScanReader with an explicit JavaScript classification. Network
// responses can be JavaScript by Content-Type even when their URL is
// extensionless, which cannot be expressed through the public source string.
func (e *Extractor) scanReader(source string, r io.Reader, isJS bool) ([]Match, error) {
	var matches []Match
	if e.isAllowed(source) {
		io.Copy(io.Discard, r)
		return matches, nil
	}
	if e.safeMode && !isJS {
		io.Copy(io.Discard, r)
		return matches, nil
	}
	buf := bufio.NewScanner(r)
	buf.Buffer(make([]byte, 0, InitialBufferSize), MaxBufferSize)
	for buf.Scan() {
		line := []byte(buf.Text())
		matches = append(matches, e.scanRulesSelected(source, line, e.rules, true)...)
	}
	return matches, buf.Err()
}

// rulesForData removes rules that provably cannot match data because one of
// their required literal prefilters is absent. The check is performed once for
// an already-buffered response instead of once per rule per line. Rules without
// a provable literal requirement, including arbitrary plugin rules, always stay
// eligible.
func (e *Extractor) rulesForData(data []byte) []Rule {
	rules := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		if e.safeMode && !e.isJSRule(rule.MatchName()) {
			continue
		}

		var prefilters [][]byte
		switch typed := rule.(type) {
		case RegexRule:
			prefilters = typed.prefilters
		case *RegexRule:
			prefilters = typed.prefilters
		}
		eligible := true
		for _, prefilter := range prefilters {
			if !bytes.Contains(data, prefilter) {
				eligible = false
				break
			}
		}
		if eligible {
			rules = append(rules, rule)
		}
	}
	return rules
}

// scanBuffered applies the same line-oriented raw rule scan as scanReader, but
// uses the complete response to discard impossible rules once up front. Keeping
// bufio.ScanLines preserves existing ^ handling, CRLF trimming and match order.
func (e *Extractor) scanBuffered(source string, data []byte, isJS bool) ([]Match, error) {
	if e.isAllowed(source) || (e.safeMode && !isJS) {
		return nil, nil
	}
	rules := e.rules
	filterSafe := true
	// A one-line minified bundle already checks each rule's prefilters once in
	// Rule.Find; a file-level pass would duplicate that work. Eligibility pays
	// off for multiline source, where it prevents the same impossible rules from
	// being reconsidered on thousands of separate lines.
	if bytes.Count(data, []byte{'\n'}) >= 32 {
		rules = e.rulesForData(data)
		filterSafe = false
	}
	var matches []Match
	buf := bufio.NewScanner(bytes.NewReader(data))
	buf.Buffer(make([]byte, 0, InitialBufferSize), MaxBufferSize)
	for buf.Scan() {
		matches = append(matches, e.scanRulesSelected(source, buf.Bytes(), rules, filterSafe)...)
	}
	return matches, buf.Err()
}

// parallelScanThreshold is the line size above which rule evaluation is spread
// across CPU cores. Minified bundles arrive as a single multi-MB line, and each
// rule scans the whole line independently, so parallelizing across rules gives
// a near-linear speedup. Small lines run sequentially to avoid goroutine churn.
const parallelScanThreshold = 128 * 1024

// scanRulesSelected applies the selected rules to line in deterministic order.
// For large lines the rules run concurrently and write into per-rule slots, so
// the merged output is identical to a sequential scan. When filterSafe is false,
// callers have already removed non-JavaScript-safe rules.
func (e *Extractor) scanRulesSelected(source string, line []byte, rules []Rule, filterSafe bool) []Match {
	applicable := func(rule Rule) bool {
		return !filterSafe || !e.safeMode || e.isJSRule(rule.MatchName())
	}

	if len(line) < parallelScanThreshold {
		var out []Match
		for _, rule := range rules {
			if !applicable(rule) {
				continue
			}
			for _, m := range rule.Find(line) {
				m.Source = source
				out = append(out, m)
			}
		}
		return out
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(rules) {
		workers = len(rules)
	}
	if workers < 1 {
		workers = 1
	}

	results := make([][]Match, len(rules))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for i := start; i < len(rules); i += workers {
				rule := rules[i]
				if !applicable(rule) {
					continue
				}
				var local []Match
				for _, m := range rule.Find(line) {
					m.Source = source
					local = append(local, m)
				}
				results[i] = local
			}
		}(w)
	}
	wg.Wait()

	var out []Match
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// ScanReaderWithEndpoints scans r like ScanReader and also extracts HTTP
// endpoints from JavaScript sources. Endpoint matches use the pattern name
// "endpoint_url" for absolute URLs and "endpoint_path" for relative paths.
func (e *Extractor) ScanReaderWithEndpoints(source string, r io.Reader) ([]Match, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return e.scanDataWithEndpoints(source, data, source == "stdin" || isJSFile(source))
}

// scanDataWithEndpoints scans already-buffered data, using isJS as the
// authoritative source classification. It combines raw regex scanning with the
// lightweight AST/value pass so secrets assembled from adjacent string literals
// are found during normal URL and CLI scans, not only through the standalone
// ScanReaderAST test API.
func (e *Extractor) scanDataWithEndpoints(source string, data []byte, isJS bool) ([]Match, error) {
	if e.isAllowed(source) {
		return nil, nil
	}
	matches, err := e.scanBuffered(source, data, isJS)
	if err != nil {
		return nil, err
	}
	if isJS {
		// Raw regex scanning already covers values that appear contiguously in the
		// source. Limit the additional AST pass to reconstructed values so a large
		// bundle does not run hundreds of rules over every ordinary string twice.
		matches = append(matches, e.scanASTData(source, data, true)...)
		matches = UniqueMatches(matches)
	}

	if isJS || looksLikeJSON(data) {
		seen := make(map[string]struct{})
		for _, ep := range parseJSEndpoints(data) {
			p := "endpoint_path"
			if ep.IsURL {
				p = "endpoint_url"
			}
			val := strings.TrimSpace(ep.Value)
			if !validEndpoint(p, val) {
				continue
			}
			key := p + "|" + val
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, Match{Source: source, Pattern: p, Value: val, Severity: "info"})
		}
	}
	if e.snippet {
		attachSnippets(data, matches)
	}
	return matches, nil
}

// ScanReaderPostRequests extracts HTTP POST request endpoints from r. Matches
// use the pattern name "post_url" for absolute URLs and "post_path" for
// relative paths. Only JavaScript files are processed when safe mode is
// enabled.
func (e *Extractor) ScanReaderPostRequests(source string, r io.Reader) ([]Match, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return e.scanDataPostRequests(source, data, source == "stdin" || isJSFile(source))
}

// scanDataPostRequests is the POST equivalent of scanDataWithEndpoints, accepting
// an explicit JavaScript classification for extensionless network responses.
func (e *Extractor) scanDataPostRequests(source string, data []byte, isJS bool) ([]Match, error) {
	if e.isAllowed(source) || !isJS {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var matches []Match
	for _, ep := range parseJSPostRequests(data) {
		p := "post_path"
		if ep.IsURL {
			p = "post_url"
		}
		val := strings.TrimSpace(ep.Value)
		params := strings.TrimSpace(ep.Params)
		key := p + "|" + val + "|" + params
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, Match{Source: source, Pattern: p, Value: val, Params: params, Severity: "info"})
	}
	if e.snippet {
		attachSnippets(data, matches)
	}
	return matches, nil
}

// FilterPostMatches returns only the matches relevant to POST-request output: the
// post_url/post_path endpoints and the crawl's gathered-URL findings. It exists so
// a -posts crawl can harvest HTML markup links to follow the link graph (emitted
// as endpoint_url matches for navigation) without those navigation-only links
// leaking into the POST-endpoint results.
func FilterPostMatches(ms []Match) []Match {
	seen := make(map[string]struct{})
	var out []Match
	for _, m := range ms {
		switch m.Pattern {
		case "post_url", "post_path", GatheredURLPattern:
		default:
			continue
		}
		key := m.Pattern + "|" + m.Value + "|" + m.Params
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

// FilterEndpointMatches returns only endpoint matches from ms.
func FilterEndpointMatches(ms []Match) []Match {
	seen := make(map[string]struct{})
	var out []Match
	for _, m := range ms {
		if !strings.HasPrefix(m.Pattern, "endpoint_") {
			continue
		}
		val := strings.TrimSpace(m.Value)
		if !validEndpoint(m.Pattern, val) {
			continue
		}
		key := m.Pattern + "|" + val
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		m.Value = val
		out = append(out, m)
	}
	return out
}

func validEndpoint(pattern, val string) bool {
	if pattern == "endpoint_url" {
		return validEndpointURL(val)
	}
	return validEndpointPath(val)
}

// noiseHostSuffixes lists documentation, library and framework domains that are
// routinely embedded in JS bundles as references but are never the target's own
// endpoints. Matching hosts are dropped from endpoint output as noise.
var noiseHostSuffixes = []string{
	"w3.org", "react.dev", "reactjs.org", "vuejs.org", "angular.io",
	"github.com", "githubusercontent.com", "github.io", "gitlab.com",
	"npmjs.com", "nodejs.org", "jquery.com", "lodash.com", "momentjs.com",
	"quilljs.com", "mozilla.org", "schema.org", "json-schema.org",
	"gnu.org", "apache.org", "opensource.org", "creativecommons.org",
}

// validEndpointURL keeps only absolute/protocol-relative URLs that point at a
// plausible, non-library host. Placeholder URLs, loopback hosts and known
// documentation/library domains are rejected.
func validEndpointURL(val string) bool {
	if val == "" || val == "//" || strings.Contains(val, "...") {
		return false
	}
	u, err := url.Parse(val)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return false
	}
	if !validHostName(host) {
		return false
	}
	for _, s := range noiseHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return false
		}
	}
	return true
}

// validHostName reports whether host is a syntactically sane DNS name: at least
// two dot-separated labels, no empty labels, and an alphabetic TLD. This rejects
// captured fragments such as "..." or single-token hosts like "a".
func validHostName(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if c := tld[i]; !(c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// validEndpointPath keeps only relative paths that look like real request
// paths. Regex fragments (`/([^\/]+)`), HTML/SVG (`/></svg>`) and code snippets
// (`/g,`, `/&`) captured from string literals are rejected. Leading `./` and
// `../` relative prefixes are permitted (e.g. `./b.js`, `../parent/api`).
func validEndpointPath(val string) bool {
	if val == "" {
		return false
	}
	// Metacharacters that indicate a regex, HTML tag or code fragment rather
	// than a path.
	if strings.ContainsAny(val, "<>()[]{}\\*,&|^$`\"' \t") {
		return false
	}
	// A trailing bare dot is a regex `.`, not a file extension.
	if strings.HasSuffix(val, ".") {
		return false
	}
	// Strip a single relative prefix so the remainder is rooted at '/'.
	rest := val
	switch {
	case strings.HasPrefix(rest, "../"):
		rest = rest[2:]
	case strings.HasPrefix(rest, "./"):
		rest = rest[1:]
	}
	if strings.HasPrefix(rest, "/") {
		// Rooted path: need at least one character after the leading slash, and it
		// must be a normal path character.
		if len(rest) < 2 || !isPathStartChar(rest[1]) {
			return false
		}
	} else {
		// Bare relative path (e.g. `api/users`): only accepted when it is
		// multi-segment (contains a `/`) and starts with a normal path character,
		// so lone tokens and non-path strings are not promoted to endpoints. Such
		// values reach here only from the request-call-anchored bareRelEndpointRe.
		if !strings.Contains(rest, "/") || !isPathStartChar(rest[0]) {
			return false
		}
	}
	// Reject empty or dot-only path segments (`/..`, `/./`).
	for _, seg := range strings.Split(strings.Trim(rest, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// isPathStartChar reports whether c is a valid first character for a URL path
// segment (letter, digit, or one of `_ - ~`).
func isPathStartChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '~'
}

// ScanReaderAST scans JavaScript source using an AST and applies regex patterns
// to all discovered string values. Only JavaScript files are processed when
// safe mode is enabled.
func (e *Extractor) ScanReaderAST(source string, r io.Reader) ([]Match, error) {
	if e.safeMode && source != "stdin" && !isJSFile(source) {
		io.Copy(io.Discard, r)
		return nil, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	matches := e.scanASTData(source, data, false)
	if e.snippet {
		attachSnippets(data, matches)
	}
	return matches, nil
}

// scanASTData applies the configured rules to literal values and simple
// literal-concatenation assignments recovered from JavaScript source.
func (e *Extractor) scanASTData(source string, data []byte, reconstructedOnly bool) []Match {
	var matches []Match
	var values []string
	if reconstructedOnly {
		values = jsast.ExtractReconstructedValues(data)
	} else {
		values = jsast.ExtractValues(data)
	}
	for _, val := range values {
		b := []byte(val)
		for _, rule := range e.rules {
			if e.safeMode && !e.isJSRule(rule.MatchName()) {
				continue
			}
			for _, m := range rule.Find(b) {
				m.Source = source
				matches = append(matches, m)
			}
		}
	}
	return matches
}
