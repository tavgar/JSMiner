package scan

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"sort"
)

// Rule defines an interface for matchers used by Extractor.
type Rule interface {
	MatchName() string
	Find(data []byte) []Match
}

// RegexRule implements Rule using a regular expression.
type RegexRule struct {
	Name     string
	RE       *regexp.Regexp
	Severity string

	// Filter, when non-nil, is applied to every regex hit. Returning false drops
	// the match. It is used to reject the large volume of false positives that
	// broad keyword/credential patterns produce on minified bundles (e.g.
	// `token:e`, `password:!0`) without weakening the patterns themselves.
	Filter func(string) bool

	// prefilters holds literal substrings that must all be present in the input
	// for RE to have any chance of matching. They are cheap byte scans used to
	// skip the far more expensive regex pass on inputs that obviously can't
	// match (e.g. running 700+ secret patterns over a multi-MB minified bundle).
	prefilters [][]byte
}

func (r RegexRule) MatchName() string { return r.Name }

func (r RegexRule) Find(data []byte) []Match {
	for _, p := range r.prefilters {
		if !bytes.Contains(data, p) {
			return nil
		}
	}
	var matches []Match
	for _, m := range r.RE.FindAll(data, -1) {
		s := string(m)
		if r.Filter != nil && !r.Filter(s) {
			continue
		}
		matches = append(matches, Match{Pattern: r.Name, Value: s, Severity: r.Severity})
	}
	return matches
}

// minPrefilterLen is the shortest literal used as a pre-filter. Short literals
// like "s3" or "use" are too common to filter usefully and would only add
// overhead, so they are ignored (the regex simply always runs for such rules).
const minPrefilterLen = 4

// newRegexRule compiles pat and derives literal pre-filters from it.
func newRegexRule(name, pat, severity string) RegexRule {
	re := regexp.MustCompile(pat)
	return RegexRule{Name: name, RE: re, Severity: severity, prefilters: requiredLiterals(pat)}
}

// requiredLiterals returns literal substrings that must appear in any string
// matched by pat. It only collects literals that lie on the unconditional match
// path (direct elements of a top-level concatenation or capture group), never
// ones under ?, *, +, or alternation, so the result is always a necessary
// condition for a match and safe to use as a pre-filter. Case-folded literals
// are skipped because a case-insensitive substring test is not worthwhile here.
// Returns nil when no useful literal can be derived.
func requiredLiterals(pat string) [][]byte {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()

	var lits [][]byte
	var walk func(r *syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpConcat:
			for _, s := range r.Sub {
				walk(s)
			}
		case syntax.OpCapture:
			if len(r.Sub) == 1 {
				walk(r.Sub[0])
			}
		case syntax.OpLiteral:
			if r.Flags&syntax.FoldCase != 0 {
				return
			}
			b := []byte(string(r.Rune))
			if len(b) >= minPrefilterLen {
				lits = append(lits, b)
			}
		}
	}
	walk(re)

	// Check the most distinctive (longest) literal first so non-matching inputs
	// are rejected on the earliest, most selective scan.
	sort.Slice(lits, func(i, j int) bool { return len(lits[i]) > len(lits[j]) })
	return lits
}

var registeredRules []Rule

// RegisterRule adds r to the global rule registry. Plugin init functions
// should call this to make their rules available.
func RegisterRule(r Rule) { registeredRules = append(registeredRules, r) }

func getRegisteredRules() []Rule { return registeredRules }
