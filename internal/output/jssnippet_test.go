package output

import (
	"strings"
	"testing"
)

func TestBeautifyJSReflowsMinified(t *testing.T) {
	src := `function f(){const a="x";if(a){return 1;}}`
	got := beautifyJS(src)
	lines := strings.Split(got, "\n")
	if len(lines) < 4 {
		t.Fatalf("expected the minified source to be split across several lines, got:\n%s", got)
	}
	// Indentation must reflect brace depth.
	if !strings.Contains(got, "\n  const a=\"x\";") {
		t.Errorf("expected `const` to be indented one level, got:\n%s", got)
	}
	if !strings.Contains(got, "\n    return 1;") {
		t.Errorf("expected `return` to be indented two levels, got:\n%s", got)
	}
}

func TestBeautifyJSPreservesBracesInsideStrings(t *testing.T) {
	// The `;` and `{}` inside the string literal must not trigger line breaks.
	src := `var re="a;b{c}d";var y=1;`
	got := beautifyJS(src)
	if !strings.Contains(got, `"a;b{c}d"`) {
		t.Fatalf("string literal was altered: %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("expected exactly one statement break, got:\n%s", got)
	}
}

func TestBeautifyJSKeepsForHeaderOnOneLine(t *testing.T) {
	got := beautifyJS(`for(i=0;i<n;i++){x();}`)
	if !strings.Contains(got, "for(i=0; i<n; i++){") {
		t.Errorf("for-header clauses should stay on one line, got:\n%s", got)
	}
}

func TestRenderSnippetPlainHasGutterAndNoAnsi(t *testing.T) {
	out := RenderSnippet(`const k="secret";`, "secret", false)
	if strings.Contains(out, "\033[") {
		t.Errorf("plain render must not contain ANSI escapes:\n%q", out)
	}
	if !strings.Contains(out, " 1 │ ") {
		t.Errorf("expected a line-number gutter, got:\n%s", out)
	}
	if !strings.Contains(out, "snippet") {
		t.Errorf("expected a snippet header, got:\n%s", out)
	}
}

func TestRenderSnippetColorEmphasizesValue(t *testing.T) {
	out := RenderSnippet(`const k="topsecret";`, "topsecret", true)
	if !strings.Contains(out, colMatch+"topsecret"+ansiReset) {
		t.Errorf("expected the value to be wrapped in the match style, got:\n%q", out)
	}
	if !strings.Contains(out, colKeyword) {
		t.Errorf("expected keyword coloring for `const`, got:\n%q", out)
	}
}

func TestClassifyTagsKeywordsAndStrings(t *testing.T) {
	s := `const x="y"`
	colors := classify(s)
	// `const` (indices 0..4) should be keyword-colored.
	if colors[0] != colKeyword {
		t.Errorf("expected `const` to be keyword-colored, got %q", colors[0])
	}
	// The opening quote of the string (index 8) should be string-colored.
	if colors[strings.Index(s, `"`)] != colString {
		t.Errorf("expected the string literal to be string-colored")
	}
}
