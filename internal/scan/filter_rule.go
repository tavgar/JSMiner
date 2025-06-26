package scan

import "regexp"

// FilterRegexRule implements Rule with an optional post-match filter.
type FilterRegexRule struct {
	Name     string
	RE       *regexp.Regexp
	Severity string
	Filter   func(string) bool
}

func (r FilterRegexRule) MatchName() string { return r.Name }

func (r FilterRegexRule) Find(data []byte) []Match {
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
