package ai

import "testing"

func TestBonusSumsMatchingRuleWeights(t *testing.T) {
	p := Compile([]Rule{
		{Pattern: `/api/`, Weight: 40, Reason: "api surface"},
		{Pattern: `\.json$`, Weight: 30, Reason: "data file"},
		{Pattern: `/blog/`, Weight: -25, Reason: "bulk content"},
	})
	cases := []struct {
		url  string
		want int
	}{
		{"https://x.test/api/data.json", 70}, // /api/ (40) + .json (30)
		{"https://x.test/api/users", 40},     // /api/ only
		{"https://x.test/blog/2020/post", -25},
		{"https://x.test/about", 0}, // no rule matches
	}
	for _, c := range cases {
		if got := p.Bonus(c.url); got != c.want {
			t.Errorf("Bonus(%q) = %d, want %d", c.url, got, c.want)
		}
	}
}

func TestBonusNilAndEmptyPolicy(t *testing.T) {
	var p *Policy
	if got := p.Bonus("https://x.test/api"); got != 0 {
		t.Errorf("nil policy Bonus = %d, want 0", got)
	}
	empty := Compile(nil)
	if got := empty.Bonus("https://x.test/api"); got != 0 {
		t.Errorf("empty policy Bonus = %d, want 0", got)
	}
	if empty.Len() != 0 {
		t.Errorf("empty policy Len = %d, want 0", empty.Len())
	}
}

func TestCompileDropsAndClampsRules(t *testing.T) {
	p := Compile([]Rule{
		{Pattern: `(`, Weight: 50},     // uncompilable -> dropped
		{Pattern: ``, Weight: 50},      // empty -> dropped
		{Pattern: `/x`, Weight: 0},     // zero weight -> dropped
		{Pattern: `/y`, Weight: 9999},  // clamped to +maxRuleWeight
		{Pattern: `/z`, Weight: -9999}, // clamped to -maxRuleWeight
		{Pattern: `/keep`, Weight: 10}, // kept as-is
	})
	if p.Len() != 3 {
		t.Fatalf("Len = %d, want 3 (bad/empty/zero-weight dropped)", p.Len())
	}
	if got := p.Bonus("https://x.test/y"); got != maxRuleWeight {
		t.Errorf("clamped positive weight = %d, want %d", got, maxRuleWeight)
	}
	if got := p.Bonus("https://x.test/z"); got != -maxRuleWeight {
		t.Errorf("clamped negative weight = %d, want %d", got, -maxRuleWeight)
	}
}

func TestBonusClampsTotal(t *testing.T) {
	// Three +100 rules all match /a/b/c; total must clamp to maxTotalBonus.
	p := Compile([]Rule{
		{Pattern: `/a`, Weight: 100},
		{Pattern: `/b`, Weight: 100},
		{Pattern: `/c`, Weight: 100},
	})
	if got := p.Bonus("https://x.test/a/b/c"); got != maxTotalBonus {
		t.Errorf("total bonus = %d, want clamp %d", got, maxTotalBonus)
	}
}

func TestCompileRespectsRuleCap(t *testing.T) {
	rules := make([]Rule, maxPolicyRules+10)
	for i := range rules {
		rules[i] = Rule{Pattern: `/p`, Weight: 1}
	}
	if got := Compile(rules).Len(); got != maxPolicyRules {
		t.Errorf("Len = %d, want cap %d", got, maxPolicyRules)
	}
}

func TestParsePolicyRulesRobustness(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int // number of rules parsed
	}{
		{"bare json", `{"version":1,"rules":[{"pattern":"/api/","weight":50}]}`, 1},
		{"prose wrapped", "Here is the policy:\n{\"version\":1,\"rules\":[{\"pattern\":\"/a\",\"weight\":1},{\"pattern\":\"/b\",\"weight\":2}]}\nDone.", 2},
		{"markdown fenced", "```json\n{\"version\":1,\"rules\":[]}\n```", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules, err := parsePolicyRules(c.text)
			if err != nil {
				t.Fatalf("parsePolicyRules error: %v", err)
			}
			if len(rules) != c.want {
				t.Errorf("got %d rules, want %d", len(rules), c.want)
			}
		})
	}
	if _, err := parsePolicyRules("no json here"); err == nil {
		t.Error("expected error when no JSON object present")
	}
}
