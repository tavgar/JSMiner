package scan

import "testing"

// TestPlausibleFormValueByType verifies that the HTML input type drives the
// value, so type-validated controls receive input they will accept.
func TestPlausibleFormValueByType(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"email", "test@example.com"},
		{"EMAIL", "test@example.com"}, // case-insensitive
		{"password", "Password123!"},
		{"number", "42"},
		{"range", "42"},
		{"tel", "5555550123"},
		{"url", "https://example.com"},
		{"date", "2024-01-01"},
		{"datetime-local", "2024-01-01T12:00"},
		{"month", "2024-01"},
		{"week", "2024-W01"},
		{"time", "12:00"},
		{"color", "#3366cc"},
		{"search", "test"},
	}
	for _, c := range cases {
		if got := plausibleFormValue(c.typ, "", "", ""); got != c.want {
			t.Errorf("plausibleFormValue(type=%q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// TestPlausibleFormValueByHint verifies that a free-text control's name, id or
// placeholder steers the value even when its type is a generic "text".
func TestPlausibleFormValueByHint(t *testing.T) {
	cases := []struct {
		name, id, ph string
		want         string
	}{
		{"email", "", "", "test@example.com"},
		{"", "", "Your e-mail address", "test@example.com"},
		{"user_password", "", "", "Password123!"},
		{"phone_number", "", "", "5555550123"},
		{"zipcode", "", "", "12345"},
		{"website", "", "", "https://example.com"},
		{"firstName", "", "", "Test"},
		{"lastName", "", "", "User"},
		{"username", "", "", "testuser"},
		{"full_name", "", "", "Test User"},
		{"city", "", "", "Springfield"},
		{"country", "", "", "US"},
		{"company", "", "", "Example Inc"},
		{"quantity", "", "", "1"},
		{"comment", "", "", "test message"},
		{"", "search-box", "", "test"},
		{"anything_else", "", "", "test"},
	}
	for _, c := range cases {
		if got := plausibleFormValue("text", c.name, c.id, c.ph); got != c.want {
			t.Errorf("plausibleFormValue(text, name=%q id=%q ph=%q) = %q, want %q",
				c.name, c.id, c.ph, got, c.want)
		}
	}
}

// TestPlausibleFormValueNeverEmpty guards the core invariant: a required text
// field must never be left blank, or a form with client-side validation will
// refuse to submit and its state stays hidden.
func TestPlausibleFormValueNeverEmpty(t *testing.T) {
	for _, typ := range []string{"", "text", "textarea", "search", "unknown-future-type"} {
		if got := plausibleFormValue(typ, "", "", ""); got == "" {
			t.Errorf("plausibleFormValue(type=%q) returned empty", typ)
		}
	}
}

// TestFormValuesKeying verifies that fillable controls are keyed by name (with
// id as a fallback) and that controls carrying no user value are skipped, so the
// map handed to the browser fills exactly the right fields.
func TestFormValuesKeying(t *testing.T) {
	f := exploreForm{
		Index: 0,
		Fields: []exploreField{
			{Tag: "input", Type: "email", Name: "email"},
			{Tag: "input", Type: "text", ID: "handle"}, // no name -> keyed by id
			{Tag: "input", Type: "hidden", Name: "csrf"},
			{Tag: "input", Type: "submit", Name: "go"},
			{Tag: "input", Type: "checkbox", Name: "agree"},
			{Tag: "input", Type: "file", Name: "upload"},
			{Tag: "input", Type: "text", Name: ""}, // no name, no id -> dropped
		},
	}
	vals := formValues(f)

	if vals["email"] != "test@example.com" {
		t.Errorf("email value = %q, want test@example.com", vals["email"])
	}
	if vals["handle"] == "" {
		t.Error("expected id-keyed field 'handle' to be filled")
	}
	for _, skip := range []string{"csrf", "go", "agree", "upload", ""} {
		if _, ok := vals[skip]; ok {
			t.Errorf("field %q should have been skipped, got %q", skip, vals[skip])
		}
	}
	if len(vals) != 2 {
		t.Errorf("expected exactly 2 filled fields, got %d: %v", len(vals), vals)
	}
}

// TestExploreMaxAttemptsBudget checks that the interaction caps scale with
// MaxExploreStates and that a disabled setting yields no budget.
func TestExploreBudgetScaling(t *testing.T) {
	orig := MaxExploreStates
	defer func() { MaxExploreStates = orig }()

	MaxExploreStates = 0
	if exploreBudget() != 0 {
		t.Errorf("disabled exploration should grant no extra budget, got %v", exploreBudget())
	}

	MaxExploreStates = 10
	if exploreMaxAttempts() != 30 {
		t.Errorf("exploreMaxAttempts() = %d, want 30", exploreMaxAttempts())
	}
	if exploreBudget() <= 0 {
		t.Error("enabled exploration should grant a positive time budget")
	}
}
