package scan

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestScanSafeModeJSFile(t *testing.T) {
	e := NewExtractor(true, false)
	r := strings.NewReader(
		"token eyJabc.def.ghi and email test@example.com " +
			"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY " +
			"AIza12345678901234567890123456789012345 " +
			"Bearer AbCdEfGhIjKlMnOpQrSt",
	)
	matches, err := e.ScanReader("script.js", r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "jwt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}

func TestScanSafeModeSkipFile(t *testing.T) {
	e := NewExtractor(true, false)
	r := strings.NewReader("eyJabc.def.ghi")
	matches, err := e.ScanReader("notes.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestScanUnsafeMode(t *testing.T) {
	e := NewExtractor(false, false)
	r := strings.NewReader("test@example.com and 1.2.3.4")
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestScanNewPatterns(t *testing.T) {
	e := NewExtractor(false, false)
	r := strings.NewReader(
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY " +
			"AIza12345678901234567890123456789012345 " +
			"Bearer AbCdEfGhIjKlMnOpQrSt",
	)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 3 {
		t.Fatalf("expected at least 3 matches, got %d", len(matches))
	}
	found := map[string]bool{}
	for _, m := range matches {
		found[m.Pattern] = true
	}
	for _, p := range []string{"aws_secret", "google_api", "bearer"} {
		if !found[p] {
			t.Fatalf("expected match for %s", p)
		}
	}
}

// TestProviderTokenPatterns verifies the value-format provider-token detectors
// fire on their distinctive shapes (as they must on minified bundles where the
// assigning keyword is gone) and do not fire on near-miss non-secrets. -longsecret
// is off so matches come from the provider rules, not the generic long_secret.
func TestProviderTokenPatterns(t *testing.T) {
	e := NewExtractor(false, false)
	src := strings.Join([]string{
		`var a="ghp_abcdefghijklmnopqrstuvwxyz0123456789";`, // github_token, mangled var
		`b("sk_live_abcdefghij1234567890");`,                // stripe_key
		`c="xoxb-1234567890-1234567890-abcdefABCDEF";`,      // slack_token
		`d="glpat-abcdefghij1234567890";`,                   // gitlab_pat
		`e="npm_abcdefghijklmnopqrstuvwxyz0123456789";`,     // npm_token
		`f="ya29.aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";`,        // google_oauth
		`g="ghp_tooShort";`,                                 // NOT github (too short)
		`h="sk_prod_abcdefghij1234567890";`,                 // NOT stripe (not live/test)
	}, "\n")
	matches, err := e.ScanReader("bundle.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, m := range matches {
		found[m.Pattern] = true
	}
	for _, p := range []string{"github_token", "stripe_key", "slack_token", "gitlab_pat", "npm_token", "google_oauth"} {
		if !found[p] {
			t.Errorf("expected a %s match", p)
		}
	}
	// Near-miss values must not be reported by any provider rule.
	for _, m := range matches {
		if m.Value == "ghp_tooShort" || m.Value == "sk_prod_abcdefghij1234567890" {
			t.Errorf("unexpected provider match on near-miss value %q (pattern %s)", m.Value, m.Pattern)
		}
	}
}

// TestAIProviderKeyPatterns verifies the LLM-provider key detectors fire on the
// vendor-assigned shapes, rank High, and are not confused by the `sk-` prefix
// they share (an OpenAI project key must not be reported as an Anthropic one).
func TestAIProviderKeyPatterns(t *testing.T) {
	e := NewExtractor(false, false)
	hex64 := strings.Repeat("a1b2c3d4", 8)
	cases := []struct{ rule, value string }{
		{"anthropic_key", "sk-ant-api03-" + strings.Repeat("Ab3-_", 18) + "AA"},
		{"openai_key", "sk-proj-" + strings.Repeat("Ab3-_", 12)},
		{"openai_legacy", "sk-" + strings.Repeat("Ab3xY9zQ", 6)},
		{"openrouter_key", "sk-or-v1-" + hex64},
		{"groq_key", "gsk_" + strings.Repeat("Ab3xY9zQ13", 5) + "ab"},
		{"xai_key", "xai-" + strings.Repeat("Ab3xY9zQ", 10)},
		{"perplexity_key", "pplx-" + strings.Repeat("Ab3xY9zQ", 4)},
		{"huggingface_token", "hf_" + strings.Repeat("AbcdefghiJ", 3) + "klmn"},
		{"replicate_key", "r8_" + strings.Repeat("Ab3xY9z", 5) + "Qz"},
		{"langsmith_key", "lsv2_pt_" + strings.Repeat("a1b2", 8) + "_" + "a1b2c3d4e5"},
	}
	var lines []string
	for i, c := range cases {
		lines = append(lines, fmt.Sprintf("var v%d=%q;", i, c.value))
	}
	matches, err := e.ScanReader("bundle.js", strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		var got *Match
		for i, m := range matches {
			if m.Pattern == c.rule {
				got = &matches[i]
				break
			}
		}
		if got == nil {
			t.Errorf("expected a %s match for %q", c.rule, c.value)
			continue
		}
		if got.Value != c.value {
			t.Errorf("%s matched %q, want %q", c.rule, got.Value, c.value)
		}
		if got.Severity != SeverityHigh {
			t.Errorf("%s severity = %q, want %q", c.rule, got.Severity, SeverityHigh)
		}
	}
	// The `sk-` family must not cross-match: each key belongs to exactly one rule.
	skRules := map[string]bool{"anthropic_key": true, "openai_key": true, "openai_legacy": true, "openrouter_key": true}
	for _, m := range matches {
		if !skRules[m.Pattern] {
			continue
		}
		for _, c := range cases {
			if m.Value == c.value && m.Pattern != c.rule {
				t.Errorf("%q matched by %s, want only %s", c.value, m.Pattern, c.rule)
			}
		}
	}
}

// TestSaaSCredentialPatterns verifies the SaaS/cloud credential detectors fire
// on each vendor's signature shape and rank High (Twilio Account SID is Medium,
// an identifier rather than a secret). Values are placed unquoted and
// space-delimited so the leading/trailing \b anchors are exercised directly.
func TestSaaSCredentialPatterns(t *testing.T) {
	e := NewExtractor(false, false)
	hex32 := strings.Repeat("a1b2c3d4", 4)
	hex64 := strings.Repeat("a1b2c3d4", 8)
	cases := []struct {
		rule, value, severity string
	}{
		{"google_oauth_secret", "GOCSPX-" + strings.Repeat("Ab3xY9z", 4), SeverityHigh},
		{"shopify_token", "shpat_" + hex32, SeverityHigh},
		{"supabase_key", "sbp_" + strings.Repeat("a1b2c3d4", 5), SeverityHigh},
		{"telegram_bot_token", "1234567890:AA" + strings.Repeat("Ab3xY9zQ", 4), SeverityHigh},
		{"discord_bot_token", "N" + strings.Repeat("Ab3", 8) + ".Ab3xY9." + strings.Repeat("Ab3xY9zQ", 4), SeverityHigh},
		{"discord_webhook", "https://discord.com/api/webhooks/12345678901234567/" + strings.Repeat("Ab3xY9zQ", 9), SeverityHigh},
		{"slack_app_token", "xapp-1-A0B1C2D3E4-1234567890-" + hex64, SeverityHigh},
		{"mapbox_secret", "sk.eyJ" + strings.Repeat("Ab3xY9zQ", 8) + "." + strings.Repeat("Ab3xY9zQ", 3), SeverityHigh},
		{"stripe_webhook_secret", "whsec_" + strings.Repeat("Ab3xY9zQ", 4), SeverityHigh},
		{"square_token", "sq0atp-" + strings.Repeat("Ab3xY9zQ", 3), SeverityHigh},
		{"mailchimp_key", hex32 + "-us21", SeverityHigh},
		{"twilio_api_key", "SK" + hex32, SeverityHigh},
		{"twilio_account_sid", "AC" + hex32, SeverityMedium},
		{"fcm_server_key", "AAAAAb3xY9z:APA91b" + strings.Repeat("Ab3xY9zQ", 17), SeverityHigh},
		{"gcp_service_account", `"type": "service_account"`, SeverityHigh},
		{"azure_storage_key", "AccountKey=" + strings.Repeat("Ab3xY9zQ", 10) + "Ab3xY9==", SeverityHigh},
		{"pypi_token", "pypi-AgEIcHlwaS" + strings.Repeat("Ab3xY9zQ", 7), SeverityHigh},
		{"postman_key", "PMAK-" + strings.Repeat("a1b2c3", 4) + "-" + hex32 + "ab", SeverityHigh},
		{"digitalocean_token", "dop_v1_" + hex64, SeverityHigh},
		{"newrelic_key", "NRAK-" + strings.Repeat("A1B2C3D4E", 3), SeverityHigh},
		{"notion_token", "secret_" + strings.Repeat("Ab3xY9zQ", 5) + "abc", SeverityHigh},
		{"doppler_token", "dp.pt." + strings.Repeat("Ab3xY9zQ", 5), SeverityHigh},
		{"databricks_token", "dapi" + hex32, SeverityHigh},
		{"planetscale_token", "pscale_pw_" + strings.Repeat("Ab3xY9zQ", 4), SeverityHigh},
		{"linear_key", "lin_api_" + strings.Repeat("Ab3xY9zQ", 5), SeverityHigh},
		{"figma_token", "figd_" + strings.Repeat("Ab3xY9zQ", 5), SeverityHigh},
		{"sentry_token", "sntrys_" + strings.Repeat("Ab3xY9zQ", 8), SeverityHigh},
		{"docker_pat", "dckr_pat_" + strings.Repeat("Ab3xY9z", 3) + "abcdef", SeverityHigh},
		{"basic_auth_url", "https://user:p4ssw0rd@internal.example.com", SeverityHigh},
	}
	var lines []string
	for i, c := range cases {
		lines = append(lines, fmt.Sprintf("x%d = %s", i, c.value))
	}
	matches, err := e.ScanReader("bundle.js", strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		var got *Match
		for i, m := range matches {
			if m.Pattern == c.rule {
				got = &matches[i]
				break
			}
		}
		if got == nil {
			t.Errorf("expected a %s match for %q", c.rule, c.value)
			continue
		}
		if got.Value != c.value {
			t.Errorf("%s matched %q, want %q", c.rule, got.Value, c.value)
		}
		if got.Severity != c.severity {
			t.Errorf("%s severity = %q, want %q", c.rule, got.Severity, c.severity)
		}
	}
}

// TestProviderTokenPatternsSafeMode confirms the provider detectors also run in
// safe mode (they are registered as JS rules), since minified JS bundles are the
// primary place these tokens leak.
func TestProviderTokenPatternsSafeMode(t *testing.T) {
	e := NewExtractor(true, false)
	matches, err := e.ScanReader("bundle.js", strings.NewReader(`x="ghp_abcdefghijklmnopqrstuvwxyz0123456789"`))
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, m := range matches {
		if m.Pattern == "github_token" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("expected github_token match in safe mode")
	}
}

func TestAllowlistIgnore(t *testing.T) {
	e := NewExtractor(false, false)
	e.allowlist = []string{"allowed.js"}
	r := strings.NewReader("eyJabc.def.ghi")
	matches, err := e.ScanReader("allowed.js", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestAllowlistSuffix(t *testing.T) {
	e := NewExtractor(false, false)
	e.allowlist = []string{"ignored.js"}
	r := strings.NewReader("eyJabc.def.ghi")
	matches, err := e.ScanReader("/path/to/ignored.js", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestScanLongLine(t *testing.T) {
	e := NewExtractor(false, false)
	longLine := strings.Repeat("a", 70*1024) + " test@example.com"
	r := strings.NewReader(longLine)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "email" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected email match, got %+v", matches)
	}
}

func TestScanLongLineSafeMode(t *testing.T) {
	e := NewExtractor(true, false)
	longLine := strings.Repeat("a", 70*1024) + " eyJabc.def.ghi"
	r := strings.NewReader(longLine)
	matches, err := e.ScanReader("script.js", r)
	if err != nil {
		t.Fatal(err)
	}
	foundJWT := false
	for _, m := range matches {
		if m.Pattern == "jwt" {
			foundJWT = true
		}
	}
	if !foundJWT {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}

func TestLoadRulesFile(t *testing.T) {
	e := NewExtractor(false, false)
	f, err := os.CreateTemp("", "rules*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	yaml := "number: \"\\d+\""
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := e.LoadRulesFile(f.Name()); err != nil {
		t.Fatal(err)
	}

	matches, err := e.ScanReader("file.txt", strings.NewReader("abc 123"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "number" {
		t.Fatalf("expected number match, got %+v", matches)
	}
}

func TestLoadRulesFileInvalid(t *testing.T) {
	e := NewExtractor(false, false)
	f, err := os.CreateTemp("", "rulesbad*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("::::"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := e.LoadRulesFile(f.Name()); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestPowerRulesDefault(t *testing.T) {
	e := NewExtractor(false, false)
	r := strings.NewReader("/tmp/data 2001:db8::1 123-456-7890")
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, m := range matches {
		found[m.Pattern] = true
	}
	for _, p := range []string{"path", "ipv6", "phone"} {
		if !found[p] {
			t.Fatalf("expected match for %s", p)
		}
	}
}

func TestSensitiveDefaults(t *testing.T) {
	e := NewExtractor(false, false)
	r := strings.NewReader(`password="secretpass" api_key=ABCDEF1234567890 token=abcdef123456`)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, m := range matches {
		if strings.HasPrefix(m.Pattern, "nuclei-") {
			continue
		}
		found[m.Pattern] = true
	}
	for _, p := range []string{"password", "api_key", "token"} {
		if !found[p] {
			t.Fatalf("expected match for %s", p)
		}
	}
}

func TestShortPasswordIgnored(t *testing.T) {
	e := NewExtractor(false, false)
	r := strings.NewReader(`password:x api_key=short token=abc`)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	var filtered []Match
	for _, m := range matches {
		if strings.HasPrefix(m.Pattern, "nuclei-") {
			continue
		}
		filtered = append(filtered, m)
	}
	if len(filtered) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(filtered))
	}
}

func TestLongSecretMatch(t *testing.T) {
	e := NewExtractor(false, true)
	secret := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	r := strings.NewReader(secret)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "long_secret" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected long_secret match, got %+v", matches)
	}
}
func TestLongSecretConcat(t *testing.T) {
	js := `var a = "?app_secret=".concat("sheiswspoke7467384638746mm5465ds45")`
	e := NewExtractor(true, true)
	matches, err := e.ScanReader("file.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if m.Pattern == "long_secret" && m.Value == "sheiswspoke7467384638746mm5465ds45" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected long_secret match, got %+v", matches)
	}
}

func BenchmarkScanReaderWithEndpointsMultiline(b *testing.B) {
	var src strings.Builder
	for i := 0; i < 10_000; i++ {
		fmt.Fprintf(&src, "const ordinary%d = \"ordinary-value-%d\";\n", i, i)
	}
	src.WriteString(`const token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789";`)
	data := src.String()
	e := NewExtractor(false, false)

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.ScanReaderWithEndpoints("bundle.js", strings.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestScanBufferedMatchesStreamingScan(t *testing.T) {
	data := []byte(strings.Repeat("ordinary line\r\n", 40) +
		`const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";` + "\n" +
		`password = "correct-horse-battery-staple"` + "\n" +
		`/var/lib/example`)
	e := NewExtractor(false, false)

	streamed, err := e.scanReader("bundle.js", bytes.NewReader(data), true)
	if err != nil {
		t.Fatal(err)
	}
	buffered, err := e.scanBuffered("bundle.js", data, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buffered, streamed) {
		t.Fatalf("buffered matches differ from streaming scan:\nbuffered: %+v\nstreamed: %+v", buffered, streamed)
	}
}
