package scan

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"jsminer/internal/scan/jsast"
)

// Match represents a single regex hit
type Match struct {
	Source  string `json:"source"`
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
}

// Extractor holds compiled regex patterns
type Extractor struct {
	patterns  map[string]*regexp.Regexp
	safeMode  bool
	allowlist []string
}

var jsExts = []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".wasm"}

var jsRules = map[string]bool{
	"jwt": true,
}

// default patterns (simplified)
var defaultPatterns = map[string]string{
	"email":      `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"ipv4":       `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
	"jwt":        `eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`,
	"aws_secret": `(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}`,
	"google_api": `AIza[0-9A-Za-z-_]{35}`,
	"bearer":     `(?i)bearer\s+[A-Za-z0-9._-]{10,}`,
}

// NewExtractor creates an Extractor
func NewExtractor(safe bool) *Extractor {
	e := &Extractor{patterns: make(map[string]*regexp.Regexp), safeMode: safe}
	for name, pat := range defaultPatterns {
		e.patterns[name] = regexp.MustCompile(pat)
	}
	return e
}

// LoadRulesFile loads additional regex patterns from a YAML file
func (e *Extractor) LoadRulesFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var rules map[string]string
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return err
	}

	for name, pat := range rules {
		r, err := regexp.Compile(pat)
		if err != nil {
			return err
		}
		e.patterns[strings.TrimSpace(name)] = r
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

func isJSRule(name string) bool {
	return jsRules[name]
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
	buf.Buffer(make([]byte, 0, 1024), 1024*1024)
	for buf.Scan() {
		line := buf.Text()
		for name, re := range e.patterns {
			if e.safeMode && !isJSRule(name) {
				continue
			}
			for _, v := range re.FindAllString(line, -1) {
				matches = append(matches, Match{Source: source, Pattern: name, Value: v})
			}
		}
	}
	return matches, buf.Err()
}

// ScanReaderWithEndpoints scans r like ScanReader and also extracts HTTP
// endpoints from JavaScript sources. Endpoint matches use the pattern name
// "endpoint".
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
		for _, ep := range parseJSEndpoints(data) {
			matches = append(matches, Match{Source: source, Pattern: "endpoint", Value: ep})
		}
	}
	return matches, nil
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
		for name, re := range e.patterns {
			if e.safeMode && !isJSRule(name) {
				continue
			}
			for _, v := range re.FindAllString(val, -1) {
				matches = append(matches, Match{Source: source, Pattern: name, Value: v})
			}
		}
	}
	return matches, nil
}
