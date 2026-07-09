package scan

import (
	"bytes"
	"unicode/utf8"
)

// snippetRadius is the number of source bytes captured on each side of a
// matched value. It is wide enough to reveal the enclosing statement or two
// after the window is beautified, while staying small enough to keep the
// captured context cheap even on multi-megabyte bundles.
const snippetRadius = 200

// attachSnippets fills Match.Snippet with a raw source window centred on each
// match's value. Matches whose value cannot be located in data (for example a
// value that was normalised after extraction) are left without a snippet. The
// captured text is trimmed to valid UTF-8 rune boundaries and marked with a
// leading/trailing ellipsis when the window does not reach the edge of data.
func attachSnippets(data []byte, matches []Match) {
	if len(data) == 0 {
		return
	}
	for i := range matches {
		v := matches[i].Value
		if v == "" {
			continue
		}
		idx := bytes.Index(data, []byte(v))
		if idx < 0 {
			continue
		}
		start := idx - snippetRadius
		if start < 0 {
			start = 0
		}
		end := idx + len(v) + snippetRadius
		if end > len(data) {
			end = len(data)
		}
		// Back off to rune boundaries so a window that slices through a
		// multi-byte character does not render as replacement glyphs.
		for start > 0 && !utf8.RuneStart(data[start]) {
			start++
		}
		for end < len(data) && !utf8.RuneStart(data[end]) {
			end--
		}

		var b []byte
		if start > 0 {
			b = append(b, "…"...)
		}
		b = append(b, data[start:end]...)
		if end < len(data) {
			b = append(b, "…"...)
		}
		matches[i].Snippet = string(b)
	}
}
