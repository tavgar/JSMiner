package scan

import "regexp"

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
}

func (r RegexRule) MatchName() string { return r.Name }

func (r RegexRule) Find(data []byte) []Match {
	var matches []Match
	for _, m := range r.RE.FindAll(data, -1) {
		matches = append(matches, Match{Pattern: r.Name, Value: string(m), Severity: r.Severity})
	}
	return matches
}

var registeredRules []Rule

// RegisterRule adds r to the global rule registry. Plugin init functions
// should call this to make their rules available.
func RegisterRule(r Rule) { registeredRules = append(registeredRules, r) }

func getRegisteredRules() []Rule { return registeredRules }
