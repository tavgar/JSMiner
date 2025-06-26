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
	"strings"

	"github.com/tavgar/JSMiner/internal/scan/jsast"
)

// Match represents a single regex hit
type Match struct {
	Source   string `json:"source"`
	Pattern  string `json:"pattern"`
	Value    string `json:"value"`
	Params   string `json:"params,omitempty"`
	Severity string `json:"severity"`
}

// Extractor holds compiled regex patterns
type Extractor struct {
	rules     []Rule
	safeMode  bool
	allowlist []string
	jsRules   map[string]bool
}

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
}

// default patterns (simplified)
var defaultPatterns = map[string]string{
	"email":      `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"ipv4":       `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
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
	// long alphanumeric strings that might be secrets
	"long_secret": `[A-Za-z0-9_-]{32,}`,
}

// powerPatterns provide additional regexes enabled by default.
var powerPatterns = map[string]string{
	"phone": `\d{3}-\d{3}-\d{4}`,
	// simple IPv6 pattern requiring at least one colon to avoid matching
	// plain decimal numbers
	"ipv6": `[0-9a-fA-F]*:[0-9a-fA-F:]+`,
	// crude file path detection for Unix and Windows paths. Requires a
	// leading whitespace or start of line to avoid matching fragments in
	// secrets.
	"path": `(?:^|\s)(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)|[A-Za-z]:\\\\(?:[^\\\\\s]+\\\\)*[^\\\\\s]+`,
}

// NewExtractor creates an Extractor
func NewExtractor(safe bool, longSecret bool) *Extractor {
	e := &Extractor{safeMode: safe, jsRules: make(map[string]bool)}
	for k, v := range baseJSRules {
		e.jsRules[k] = v
	}
	for name, pat := range defaultPatterns {
		if name == "long_secret" && !longSecret {
			continue
		}
		e.rules = append(e.rules, RegexRule{Name: name, RE: regexp.MustCompile(pat), Severity: "info"})
		if name == "long_secret" {
			e.jsRules[name] = true
		}
	}
	for name, pat := range powerPatterns {
		e.rules = append(e.rules, RegexRule{Name: name, RE: regexp.MustCompile(pat), Severity: "info"})
	}
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

func isJSFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range jsExts {
		if ext == e {
			return true
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
	var matches []Match
	if e.isAllowed(source) {
		io.Copy(io.Discard, r)
		return matches, nil
	}
	if e.safeMode && source != "stdin" && !isJSFile(source) {
		io.Copy(io.Discard, r)
		return matches, nil
	}
	buf := bufio.NewScanner(r)
	buf.Buffer(make([]byte, 0, InitialBufferSize), MaxBufferSize)
	for buf.Scan() {
		line := []byte(buf.Text())
		for _, rule := range e.rules {
			if e.safeMode && !e.isJSRule(rule.MatchName()) {
				continue
			}
			for _, m := range rule.Find(line) {
				m.Source = source
				matches = append(matches, m)
			}
		}
	}
	return matches, buf.Err()
}

// ScanReaderWithEndpoints scans r like ScanReader and also extracts HTTP
// endpoints from JavaScript sources. Endpoint matches use the pattern name
// "endpoint_url" for absolute URLs and "endpoint_path" for relative paths.
func (e *Extractor) ScanReaderWithEndpoints(source string, r io.Reader) ([]Match, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	matches, err := e.ScanReader(source, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if source == "stdin" || isJSFile(source) {
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
	return matches, nil
}

// ScanReaderPostRequests extracts HTTP POST request endpoints from r. Matches
// use the pattern name "post_url" for absolute URLs and "post_path" for
// relative paths. Only JavaScript files are processed when safe mode is
// enabled.
func (e *Extractor) ScanReaderPostRequests(source string, r io.Reader) ([]Match, error) {
	if e.safeMode && source != "stdin" && !isJSFile(source) {
		io.Copy(io.Discard, r)
		return nil, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if source != "stdin" && !isJSFile(source) {
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
	return matches, nil
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
		u, err := url.Parse(val)
		if err != nil || u.Hostname() == "" {
			return false
		}
		host := strings.ToLower(u.Hostname())
		if strings.HasSuffix(host, "w3.org") {
			return false
		}
		if !strings.Contains(host, ".") && net.ParseIP(host) == nil && host != "localhost" {
			return false
		}
		if val == "//" {
			return false
		}
	} else {
		if val == "" || val == "/" || val == "//" || val == "/./" || val == "/$" || val == "/*" || val == "./" || val == "../" {
			return false
		}
	}
	return true
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
	var matches []Match
	for _, val := range jsast.ExtractValues(data) {
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
	return matches, nil
}
