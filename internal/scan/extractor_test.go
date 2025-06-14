package scan

import (
	"os"
	"strings"
	"testing"
)

func TestScanSafeModeJSFile(t *testing.T) {
	e := NewExtractor(true)
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
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match only, got %+v", matches)
	}
}

func TestScanSafeModeSkipFile(t *testing.T) {
	e := NewExtractor(true)
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
	e := NewExtractor(false)
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
	e := NewExtractor(false)
	r := strings.NewReader(
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY " +
			"AIza12345678901234567890123456789012345 " +
			"Bearer AbCdEfGhIjKlMnOpQrSt",
	)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
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

func TestAllowlistIgnore(t *testing.T) {
	e := NewExtractor(false)
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
	e := NewExtractor(false)
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
	e := NewExtractor(false)
	longLine := strings.Repeat("a", 70*1024) + " test@example.com"
	r := strings.NewReader(longLine)
	matches, err := e.ScanReader("file.txt", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "email" {
		t.Fatalf("expected email match only, got %+v", matches)
	}
}

func TestScanLongLineSafeMode(t *testing.T) {
	e := NewExtractor(true)
	longLine := strings.Repeat("a", 70*1024) + " eyJabc.def.ghi"
	r := strings.NewReader(longLine)
	matches, err := e.ScanReader("script.js", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match only, got %+v", matches)
	}
}

func TestLoadRulesFile(t *testing.T) {
	e := NewExtractor(false)
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
	e := NewExtractor(false)
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
	e := NewExtractor(false)
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
