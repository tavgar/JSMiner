package output

import (
	"fmt"
	"strconv"
	"strings"
)

// ANSI colors used for JavaScript syntax highlighting. Foreground colors are
// deliberately restrained so the highlighted finding still stands out.
const (
	ansiReset  = "\033[0m"
	colKeyword = "\033[35m"     // magenta - keywords (function, const, return, ...)
	colString  = "\033[32m"     // green   - string / template literals
	colNumber  = "\033[36m"     // cyan    - numeric literals
	colComment = "\033[90m"     // gray    - comments
	colLiteral = "\033[33m"     // yellow  - true/false/null/this/...
	colGutter  = "\033[90m"     // gray    - line-number gutter and rules
	colMatch   = "\033[1;4;93m" // bold underlined bright yellow - the finding
)

var jsKeywords = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true,
	"continue": true, "debugger": true, "default": true, "delete": true, "do": true,
	"else": true, "export": true, "extends": true, "finally": true, "for": true,
	"function": true, "if": true, "import": true, "in": true, "instanceof": true,
	"new": true, "return": true, "super": true, "switch": true, "throw": true,
	"try": true, "typeof": true, "var": true, "void": true, "while": true,
	"with": true, "yield": true, "let": true, "static": true, "async": true,
	"await": true, "of": true, "from": true, "as": true, "get": true, "set": true,
}

var jsLiterals = map[string]bool{
	"true": true, "false": true, "null": true, "undefined": true,
	"NaN": true, "Infinity": true, "this": true,
}

// RenderSnippet turns a raw source window into a prettified, optionally
// syntax-highlighted code excerpt laid out with a line-number gutter. value is
// emphasized wherever it appears in the excerpt. When color is false the same
// layout is produced without ANSI escapes (suitable for files or pipes).
func RenderSnippet(raw, value string, color bool) string {
	pretty := beautifyJS(raw)
	if pretty == "" {
		return ""
	}

	// Locate the finding within the beautified excerpt so it can be
	// emphasized. Beautifying never rewrites string contents, so a value that
	// lived inside a literal is found verbatim; values split across inserted
	// line breaks simply go unhighlighted.
	ms, me := -1, -1
	if value != "" {
		if idx := strings.Index(pretty, value); idx >= 0 {
			ms, me = idx, idx+len(value)
		}
	}

	var colors []string
	if color {
		colors = classify(pretty)
	}

	lines := strings.Split(pretty, "\n")
	width := len(strconv.Itoa(len(lines)))

	var b strings.Builder
	rule := strings.Repeat("─", 40)
	if color {
		fmt.Fprintf(&b, "    %s┌─ snippet %s%s\n", colGutter, rule, ansiReset)
	} else {
		fmt.Fprintf(&b, "    ┌─ snippet %s\n", rule)
	}

	pos := 0
	for i, line := range lines {
		num := fmt.Sprintf("%*d", width, i+1)
		if color {
			fmt.Fprintf(&b, "    %s%s │%s ", colGutter, num, ansiReset)
			renderColoredLine(&b, pretty, colors, pos, pos+len(line), ms, me)
		} else {
			fmt.Fprintf(&b, "    %s │ %s", num, line)
		}
		b.WriteByte('\n')
		pos += len(line) + 1 // account for the split '\n'
	}

	if color {
		fmt.Fprintf(&b, "    %s└─%s%s\n", colGutter, rule, ansiReset)
	} else {
		fmt.Fprintf(&b, "    └─%s\n", rule)
	}
	return b.String()
}

// BeautifySnippet returns just the prettified JavaScript for the raw window,
// without any layout or coloring. It is used for structured (JSON) output.
func BeautifySnippet(raw string) string {
	return beautifyJS(raw)
}

// renderColoredLine writes the bytes pretty[start:end] to b, applying the
// per-byte syntax colors and overriding them with the match style for any byte
// inside the global [ms,me) region. Consecutive bytes sharing a style are
// emitted as a single escaped run to keep the output compact.
func renderColoredLine(b *strings.Builder, pretty string, colors []string, start, end, ms, me int) {
	i := start
	for i < end {
		emph := i >= ms && i < me
		style := colors[i]
		if emph {
			style = colMatch
		}
		j := i + 1
		for j < end {
			nextEmph := j >= ms && j < me
			nextStyle := colors[j]
			if nextEmph {
				nextStyle = colMatch
			}
			if nextEmph != emph || nextStyle != style {
				break
			}
			j++
		}
		if style != "" {
			b.WriteString(style)
			b.WriteString(pretty[i:j])
			b.WriteString(ansiReset)
		} else {
			b.WriteString(pretty[i:j])
		}
		i = j
	}
}

// classify returns a per-byte foreground color for s. Bytes with no specific
// color (punctuation, whitespace, plain identifiers) map to an empty string.
func classify(s string) []string {
	n := len(s)
	colors := make([]string, n)
	fill := func(a, c int, col string) {
		for k := a; k < c; k++ {
			colors[k] = col
		}
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isIdentStart := func(c byte) bool {
		return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	isIdentPart := func(c byte) bool { return isIdentStart(c) || isDigit(c) }

	i := 0
	for i < n {
		c := s[i]
		switch {
		case c == '/' && i+1 < n && s[i+1] == '/':
			j := i + 2
			for j < n && s[j] != '\n' {
				j++
			}
			fill(i, j, colComment)
			i = j
		case c == '/' && i+1 < n && s[i+1] == '*':
			j := i + 2
			for j < n && !(s[j] == '*' && j+1 < n && s[j+1] == '/') {
				j++
			}
			if j < n {
				j += 2
			}
			fill(i, j, colComment)
			i = j
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < n {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == c {
					j++
					break
				}
				j++
			}
			fill(i, j, colString)
			i = j
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(s[i+1])):
			j := i + 1
			for j < n && (isIdentPart(s[j]) || s[j] == '.') {
				j++
			}
			fill(i, j, colNumber)
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			switch w := s[i:j]; {
			case jsKeywords[w]:
				fill(i, j, colKeyword)
			case jsLiterals[w]:
				fill(i, j, colLiteral)
			}
			i = j
		default:
			i++
		}
	}
	return colors
}

// beautifyJS reflows compact/minified JavaScript onto indented lines by
// breaking after '{', '}' and ';' and indenting by brace depth. It tracks
// string, template and comment context so structural characters inside those
// constructs are left untouched, and it collapses redundant whitespace. It is a
// display-only formatter: correctness of the reflow is best-effort (regular
// expression literals, for example, are treated as ordinary tokens), which is
// acceptable for a bounded excerpt.
func beautifyJS(src string) string {
	var b strings.Builder
	indent := 0
	parenDepth := 0
	n := len(src)
	lineHasContent := false
	pendingSpace := false

	newline := func() {
		b.WriteByte('\n')
		for k := 0; k < indent; k++ {
			b.WriteString("  ")
		}
		lineHasContent = false
		pendingSpace = false
	}
	writeText := func(text string) {
		if pendingSpace && lineHasContent {
			b.WriteByte(' ')
		}
		pendingSpace = false
		b.WriteString(text)
		lineHasContent = true
	}

	i := 0
	for i < n {
		c := src[i]

		// String and template literals: copy verbatim.
		if c == '"' || c == '\'' || c == '`' {
			j := i + 1
			for j < n {
				if src[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if src[j] == c {
					j++
					break
				}
				j++
			}
			writeText(src[i:j])
			i = j
			continue
		}
		// Line comment.
		if c == '/' && i+1 < n && src[i+1] == '/' {
			j := i + 2
			for j < n && src[j] != '\n' {
				j++
			}
			writeText(src[i:j])
			i = j
			continue
		}
		// Block comment.
		if c == '/' && i+1 < n && src[i+1] == '*' {
			j := i + 2
			for j < n && !(src[j] == '*' && j+1 < n && src[j+1] == '/') {
				j++
			}
			if j < n {
				j += 2
			}
			writeText(src[i:j])
			i = j
			continue
		}

		switch c {
		case '{':
			writeText("{")
			indent++
			newline()
		case '}':
			if indent > 0 {
				indent--
			}
			if lineHasContent {
				newline()
			} else {
				// Re-indent the current (blank) line to the reduced depth.
				trimTrailingIndent(&b)
				for k := 0; k < indent; k++ {
					b.WriteString("  ")
				}
			}
			b.WriteByte('}')
			lineHasContent = true
			// Deliberately no line break here: trailing punctuation such as
			// ")", ";" or a ".then(...)" chain stays attached to the brace,
			// e.g. "}).then(...);" rather than orphaned on its own line.
		case ';':
			writeText(";")
			// Keep the clauses of a for-header (for(a;b;c)) on one line;
			// only real statement terminators start a new line.
			if parenDepth == 0 {
				newline()
			} else {
				pendingSpace = true
			}
		case '(':
			parenDepth++
			writeText("(")
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			writeText(")")
		case ' ', '\t', '\r', '\n':
			if lineHasContent {
				pendingSpace = true
			}
		default:
			writeText(string(c))
		}
		i++
	}

	// Drop trailing-whitespace-only and empty lines for a clean result.
	raw := b.String()
	outLines := make([]string, 0)
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimRight(ln, " \t")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		outLines = append(outLines, ln)
	}
	return strings.Join(outLines, "\n")
}

// trimTrailingIndent removes trailing space characters from the end of b so a
// closing brace can be re-indented. It rebuilds the builder because
// strings.Builder has no truncate operation.
func trimTrailingIndent(b *strings.Builder) {
	s := strings.TrimRight(b.String(), " ")
	b.Reset()
	b.WriteString(s)
}
