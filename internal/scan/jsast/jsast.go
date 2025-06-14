package jsast

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// ExtractValues parses JavaScript source and returns string values found in
// string literals, template strings and simple variable assignments.
func ExtractValues(data []byte) []string {
	l := js.NewLexer(parse.NewInputBytes(data))
	var values []string

	var expectAssign bool
	var assignActive bool
	var buf []string

	for {
		tt, lit := l.Next()
		if tt == js.ErrorToken {
			break
		}
		switch tt {
		case js.StringToken:
			s, _ := strconv.Unquote(string(lit))
			if assignActive {
				buf = append(buf, s)
			}
			values = append(values, s)
		case js.TemplateToken:
			if assignActive {
				buf = append(buf, string(lit))
			}
			values = append(values, string(lit))
		case js.IdentifierToken:
			expectAssign = true
		case js.KeywordToken:
			if bytes.Equal(lit, []byte("var")) || bytes.Equal(lit, []byte("let")) || bytes.Equal(lit, []byte("const")) {
				expectAssign = true
			} else {
				expectAssign = false
			}
		case js.PunctuatorToken:
			if expectAssign && bytes.Equal(lit, []byte("=")) {
				assignActive = true
				buf = nil
				expectAssign = false
			} else if assignActive {
				if !bytes.Equal(lit, []byte("+")) {
					assignActive = false
					if len(buf) > 0 {
						values = append(values, strings.Join(buf, ""))
					}
					buf = nil
				}
			} else {
				expectAssign = false
			}
		default:
			if assignActive {
				assignActive = false
				if len(buf) > 0 {
					values = append(values, strings.Join(buf, ""))
				}
				buf = nil
			}
			expectAssign = false
		}
	}
	if assignActive && len(buf) > 0 {
		values = append(values, strings.Join(buf, ""))
	}
	return values
}
