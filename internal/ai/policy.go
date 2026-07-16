// Package ai provides an optional, provider-agnostic helper that lets a language
// model steer the crawler's frontier priority without touching the crawl's hot
// path. A model is consulted at most twice per crawl to turn a compact digest of
// the target's URL structure (see SiteDigest) into a small, deterministic scoring
// Policy; the crawler then applies that policy to every discovered URL in pure Go,
// so per-URL scoring stays zero-token and fully reproducible.
//
// The package never imports the scan package (scan imports it), has no hard
// dependency on any single provider, and is designed to fail open: when it is
// disabled, unconfigured or the API call fails, callers fall back to the built-in
// heuristic scorer and the crawl proceeds exactly as before.
package ai

import (
	"net/url"
	"regexp"
	"strings"
)

// policyVersion is bumped when the on-disk policy cache format changes; a cached
// policy written by a different version is ignored rather than misread.
const policyVersion = 1

// Score bounds. The built-in heuristic scorer rates a URL in roughly the 40–100
// band (see scan.targetScore), so a policy rule's influence is clamped to keep it
// a nudge rather than an override: no single rule can swing a URL by more than
// maxRuleWeight, and the summed bonus for any URL is clamped to maxTotalBonus.
// This bounds how far a (possibly imperfect) model-authored policy can distort the
// deterministic ordering.
const (
	maxRuleWeight  = 100
	maxTotalBonus  = 200
	maxPolicyRules = 64 // ignore anything beyond this; keeps a runaway policy cheap
)

// Rule is one entry of a scoring policy: a regular expression matched against a
// URL's path, a signed Weight added to the URL's base score when it matches, and a
// short human-readable Reason (surfaced only in verbose logs). Rules are authored
// by the model and are treated as untrusted input — see compile.
type Rule struct {
	Pattern string `json:"pattern"`
	Weight  int    `json:"weight"`
	Reason  string `json:"reason,omitempty"`
}

// compiledRule is a Rule whose pattern has been compiled and whose weight has been
// clamped, ready for cheap repeated matching at push time.
type compiledRule struct {
	re     *regexp.Regexp
	weight int
	rule   Rule
}

// Policy is a compiled, validated set of scoring rules. The zero value and a nil
// *Policy are both safe: Bonus returns 0, so callers can hold a *Policy
// unconditionally and let a disabled/absent policy contribute nothing.
type Policy struct {
	rules []compiledRule
}

// wirePolicy is the JSON shape exchanged with the model and stored in the cache.
// It is deliberately separate from Policy so the compiled form never has to be
// serialised and so malformed rules can be dropped on load.
type wirePolicy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Compile turns a set of raw rules into a Policy, dropping any rule that cannot be
// used: an empty or uncompilable pattern, or a zero effective weight. Each weight
// is clamped to ±maxRuleWeight and at most maxPolicyRules rules are kept. Dropping
// rather than erroring keeps the feature fail-open — a partly-malformed model
// response still yields a usable (or empty) policy. It never returns nil; an
// all-invalid input yields an empty Policy whose Bonus is always 0.
func Compile(rules []Rule) *Policy {
	p := &Policy{}
	for _, r := range rules {
		if len(p.rules) >= maxPolicyRules {
			break
		}
		pat := strings.TrimSpace(r.Pattern)
		if pat == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + pat)
		if err != nil {
			continue
		}
		w := clamp(r.Weight, -maxRuleWeight, maxRuleWeight)
		if w == 0 {
			continue
		}
		p.rules = append(p.rules, compiledRule{re: re, weight: w, rule: Rule{Pattern: pat, Weight: w, Reason: r.Reason}})
	}
	return p
}

// Bonus returns the score adjustment the policy assigns to rawURL: the sum of the
// weights of every rule whose pattern matches the URL's path, clamped to
// ±maxTotalBonus. A nil policy, an empty policy or an unparseable URL all yield 0,
// so the caller's ordering is simply the built-in score in those cases.
func (p *Policy) Bonus(rawURL string) int {
	if p == nil || len(p.rules) == 0 {
		return 0
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	// Match against the path (which carries the file extension and route names);
	// a leading "/" is guaranteed for absolute URLs and harmless otherwise.
	path := u.Path
	if path == "" {
		path = "/"
	}
	total := 0
	for _, cr := range p.rules {
		if cr.re.MatchString(path) {
			total += cr.weight
		}
	}
	return clamp(total, -maxTotalBonus, maxTotalBonus)
}

// Len reports how many rules the policy holds, for verbose logging and tests.
func (p *Policy) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rules)
}

// Rules returns the policy's effective (compiled, clamped) rules, for verbose
// logging and tests. The returned slice is a copy the caller may not mutate into
// the policy.
func (p *Policy) Rules() []Rule {
	if p == nil {
		return nil
	}
	out := make([]Rule, len(p.rules))
	for i, cr := range p.rules {
		out[i] = cr.rule
	}
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
