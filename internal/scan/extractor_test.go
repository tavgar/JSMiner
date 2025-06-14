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
