package scan

import "testing"
import "strings"

func TestExtractor(t *testing.T) {
	e := NewExtractor(true)
	r := strings.NewReader("test email test@example.com and IP 1.2.3.4")
	matches, err := e.ScanReader("test", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestAllowlistValue(t *testing.T) {
	e := NewExtractor(true)
	e.allowlist = []string{"example.com"}
	r := strings.NewReader("email test@example.com and IP 1.2.3.4")
	matches, err := e.ScanReader("src", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Pattern != "ipv4" {
		t.Fatalf("expected ipv4 match, got %s", matches[0].Pattern)
	}
}

func TestAllowlistSource(t *testing.T) {
	e := NewExtractor(true)
	e.allowlist = []string{"mysite.com"}
	r := strings.NewReader("token eyJhbGciOiJ.test")
	matches, err := e.ScanReader("mysite.com/script.js", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}
