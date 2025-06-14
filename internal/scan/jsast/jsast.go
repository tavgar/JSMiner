package jsast

import (
	"regexp"
	"strconv"
	"strings"
)

// ExtractValues parses JavaScript source and returns string values found in
// string literals and simple variable assignments where the value consists of
// one or more string literals concatenated with '+'. The implementation is
// intentionally lightweight and does not rely on external parsing libraries.
func ExtractValues(data []byte) []string {
	src := string(data)
	uniq := make(map[string]struct{})

	// regular expression for JavaScript string literals
	pattern := `(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`" + `(?:\\.|[^\\` + "`" + `])*` + "`"
	strRe := regexp.MustCompile(pattern)
	for _, m := range strRe.FindAllString(src, -1) {
		if v, err := strconv.Unquote(m); err == nil {
			uniq[v] = struct{}{}
		} else {
			uniq[strings.Trim(m, "'\"`")] = struct{}{}
		}
	}

	// match simple assignments like: const a = "foo" + "bar";
	assignRe := regexp.MustCompile(`(?m)(?:var|let|const)\s+\w+\s*=\s*([^;\n]+)`)
	for _, m := range assignRe.FindAllStringSubmatch(src, -1) {
		expr := m[1]
		parts := strings.Split(expr, "+")
		var sb strings.Builder
		ok := true
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strRe.MatchString(p) {
				ok = false
				break
			}
			if v, err := strconv.Unquote(p); err == nil {
				sb.WriteString(v)
			} else {
				sb.WriteString(strings.Trim(p, "'\"`"))
			}
		}
		if ok {
			uniq[sb.String()] = struct{}{}
		}
	}

	out := make([]string, 0, len(uniq))
	for v := range uniq {
		out = append(out, v)
	}
	return out
}
