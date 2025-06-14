package scan

import (
	"strings"
	"testing"
)

func TestScanReaderASTVar(t *testing.T) {
	src := `const t = "eyJabc.def.ghi"`
	e := NewExtractor(true)
	matches, err := e.ScanReaderAST("script.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}

func TestScanReaderASTConcat(t *testing.T) {
	src := `const t = "eyJabc." + "def.ghi"`
	e := NewExtractor(true)
	matches, err := e.ScanReaderAST("script.js", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Pattern != "jwt" {
		t.Fatalf("expected jwt match, got %+v", matches)
	}
}
