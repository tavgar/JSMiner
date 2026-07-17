package jsast

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// These expressions are used for every JavaScript response. Compiling them
	// once avoids repeating regexp parsing and machine construction per page.
	stringLiteralRe = regexp.MustCompile(
		`(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`" + `(?:\\.|[^\\` + "`" + `])*` + "`",
	)
	assignmentRe             = regexp.MustCompile(`(?m)(?:var|let|const)\s+\w+\s*=\s*([^;\n]+)`)
	concatenatedAssignmentRe = regexp.MustCompile(`(?m)(?:var|let|const)\s+\w+\s*=\s*([^;\n]*\+[^;\n]+)`)
)

func decodeStringLiteral(literal string) string {
	if value, err := strconv.Unquote(literal); err == nil {
		return value
	}
	return strings.Trim(literal, "'\"`")
}

func addAssignedValues(src string, add func(string)) {
	for _, match := range assignmentRe.FindAllStringSubmatch(src, -1) {
		parts := strings.Split(match[1], "+")
		var value strings.Builder
		valid := true
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if !stringLiteralRe.MatchString(part) {
				valid = false
				break
			}
			value.WriteString(decodeStringLiteral(part))
		}
		if valid {
			add(value.String())
		}
	}
}

// ExtractValues parses JavaScript source and returns string values found in
// string literals and simple variable assignments where the value consists of
// one or more string literals concatenated with '+'. The implementation is
// intentionally lightweight and does not rely on external parsing libraries.
func ExtractValues(data []byte) []string {
	src := string(data)
	uniq := make(map[string]struct{})

	for _, match := range stringLiteralRe.FindAllString(src, -1) {
		uniq[decodeStringLiteral(match)] = struct{}{}
	}

	// Match simple assignments like: const a = "foo" + "bar";
	addAssignedValues(src, func(value string) { uniq[value] = struct{}{} })

	out := make([]string, 0, len(uniq))
	for v := range uniq {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ExtractReconstructedValues returns the same values ExtractValues would return
// after removing values whose bytes already occur contiguously in data. Normal
// scans have already applied every regex rule to the raw source, so only decoded
// escapes and literal concatenations absent from the source need the additional
// value pass.
//
// Checking ordinary literals against their own token first is important for
// large bundles: almost all values are already present there, which avoids an
// otherwise quadratic whole-buffer bytes.Contains scan for every string.
func ExtractReconstructedValues(data []byte) []string {
	uniq := make(map[string]struct{})
	addIfReconstructed := func(value string) {
		if !bytes.Contains(data, []byte(value)) {
			uniq[value] = struct{}{}
		}
	}

	for _, match := range stringLiteralRe.FindAll(data, -1) {
		// With no escape sequence, decoding cannot produce bytes that are absent
		// from the literal itself. Avoid allocating a Go string for the normal
		// case, which accounts for nearly every literal in production bundles.
		if !bytes.ContainsRune(match, '\\') {
			continue
		}
		value := decodeStringLiteral(string(match))
		// The common unescaped-literal case can be rejected by inspecting only
		// its small token rather than searching the complete bundle.
		if bytes.Contains(match, []byte(value)) {
			continue
		}
		addIfReconstructed(value)
	}

	// A single-literal assignment cannot add anything beyond the literal pass:
	// its decoded value is handled above, while any non-literal fallback is
	// already a contiguous source substring. Only '+' expressions can construct
	// a value that the raw rule scan did not see.
	for _, match := range concatenatedAssignmentRe.FindAllSubmatch(data, -1) {
		parts := bytes.Split(match[1], []byte("+"))
		var value strings.Builder
		valid := true
		for _, part := range parts {
			part = bytes.TrimSpace(part)
			if !stringLiteralRe.Match(part) {
				valid = false
				break
			}
			value.WriteString(decodeStringLiteral(string(part)))
		}
		if valid {
			addIfReconstructed(value.String())
		}
	}

	out := make([]string, 0, len(uniq))
	for value := range uniq {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
