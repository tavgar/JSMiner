package scan

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	// simple YAML key:value
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		line := lines.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return errors.New("invalid rules line")
		}
		name := strings.TrimSpace(parts[0])
		pat := strings.TrimSpace(parts[1])
		r, err := regexp.Compile(pat)
		if err != nil {
			return err
		}
		e.patterns[name] = r
	}
	return lines.Err()
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
