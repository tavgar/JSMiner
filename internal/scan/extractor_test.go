package scan

import (
	"strings"
	"testing"
)

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

func TestExtractorJSString(t *testing.T) {
	e := NewExtractor(true)
	src := `const token = "eyJabc.def.ghi";`
	matches, err := e.ScanReader("example.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %#v", matches)
	}
}

func TestExtractorJSTemplate(t *testing.T) {
	e := NewExtractor(true)
	src := "const tmpl = `token: eyJabc.def.ghi`;"
	matches, err := e.ScanReader("example.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %#v", matches)
	}
}
