package scan

import (
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
