package scan

import (
	"net"
	"regexp"
	"strings"
)

// This file centralizes the heuristics that separate genuine findings from the
// large volume of noise that broad regex rules generate when run over minified
// JavaScript bundles. Minified code is packed with short identifiers, object
// literals, SVG path data and CSS pseudo-selectors that superficially resemble
// IPs, credentials and endpoints. The helpers below encode cheap, well-scoped
// signals that reject those look-alikes while preserving the high-value hits a
// user actually cares about (real tokens, keys, hosts and API paths).

// kebabWordRE matches all-lowercase kebab-case identifiers such as
// "css-var-root" or "current-password". These are configuration/CSS names, never
// secret values, so they are rejected as credential values. Values containing
// digits (hashes, UUIDs, real keys) are intentionally not matched.
var kebabWordRE = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+$`)

// commonNonSecret holds lowercase words that frequently appear on the value side
// of a "keyword: value" match in minified code but are never real secrets:
// JS keywords, DOM/property names and type names. Compared case-insensitively.
var commonNonSecret = map[string]bool{
	"function": true, "undefined": true, "prototype": true, "constructor": true,
	"arguments": true, "boolean": true, "default": true, "disabled": true,
	"readonly": true, "required": true, "autofocus": true, "placeholder": true,
	"autocomplete": true, "nodename": true, "nodetype": true, "innerhtml": true,
	"classname": true, "children": true, "current": true, "password": true,
	"username": true, "checkbox": true, "textarea": true, "onchange": true,
	"onsubmit": true, "returnvalue": true, "stringify": true, "typeof": true,
	"instanceof": true, "tostring": true, "valueof": true, "element": true,
	"document": true, "location": true, "navigator": true, "properties": true,
	// JS globals / built-ins that show up as identifier values in minified code.
	"object": true, "array": true, "string": true, "number": true, "symbol": true,
	"promise": true, "error": true, "window": true, "global": true, "buffer": true,
	"regexp": true, "weakmap": true, "weakset": true, "reflect": true, "proxy": true,
}

// looksLikeSecretValue reports whether v, the value on the right-hand side of a
// keyword/credential match, is plausibly a real secret rather than a minified
// identifier, boolean flag or config word. It is deliberately conservative:
// short values (the overwhelming majority of minifier output like `e`, `Se`,
// `!0`) and dictionary-ish words are dropped, while length or entropy that is
// characteristic of tokens and keys is kept.
func looksLikeSecretValue(v string) bool {
	v = strings.Trim(v, "\"'` ")
	// Real secrets embedded in JS are longer than a minified variable name.
	if len(v) < 6 {
		return false
	}
	lower := strings.ToLower(v)
	if commonNonSecret[lower] {
		return false
	}
	// Kebab-case words (CSS vars, ARIA/autocomplete tokens) are never secrets.
	if kebabWordRE.MatchString(v) {
		return false
	}
	return true
}

// credentialValue extracts the value token that follows the first ':' or '='
// separator in a keyword/credential match. It stops at the first character that
// cannot be part of a secret so that surrounding minified code (`password:a.b`,
// `token:new,`) does not leak into the value.
func credentialValue(s string) string {
	i := strings.IndexAny(s, ":=")
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeft(s[i+1:], " \t\"'`")
	j := 0
	for j < len(rest) {
		c := rest[j]
		if c == '_' || c == '-' ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			j++
			continue
		}
		break
	}
	return rest[:j]
}

// credentialValueFilter is attached to broad "keyword <sep> value" rules (the
// generic nuclei patterns and the default password/token/api_key rules). It
// keeps a match only when the extracted value looks like a genuine secret.
func credentialValueFilter(s string) bool {
	return looksLikeSecretValue(credentialValue(s))
}

// isKeywordValuePattern reports whether a regex pattern ends with the generic
// "<separator> value" tail shared by the noisy nuclei credential rules. Strict,
// self-describing formats (AWS keys, GitHub PATs, JWTs, bearer tokens, ...) do
// not end this way and are left untouched so their precision is preserved.
func isKeywordValuePattern(pat string) bool {
	return strings.HasSuffix(pat, `[\w-]+["']?`) ||
		strings.HasSuffix(pat, `[\w-]+["']`) ||
		strings.HasSuffix(pat, `.+["']`)
}

// ipv4Pattern is a strict dotted-quad: each octet 0-255 with no leading zeros.
// This alone discards the leading-zero decimal runs (e.g. "05.09.12.12") that
// SVG path data produces.
const ipv4Pattern = `\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`

// ipv4Rule detects IPv4 addresses while rejecting the dotted-decimal streams
// (SVG path data, coordinate/version arrays) that dominate minified bundles.
// Those streams are sequences of space/comma-separated decimals, so a candidate
// that borders another number on either side is treated as numeric data rather
// than an address. Context is needed for this decision, so ipv4 is a dedicated
// Rule rather than a plain regex + value filter.
type ipv4Rule struct{ re *regexp.Regexp }

func newIPv4Rule() ipv4Rule { return ipv4Rule{re: regexp.MustCompile(ipv4Pattern)} }

func (ipv4Rule) MatchName() string { return "ipv4" }

func (r ipv4Rule) Find(data []byte) []Match {
	var out []Match
	for _, loc := range r.re.FindAllIndex(data, -1) {
		s := string(data[loc[0]:loc[1]])
		if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
			continue
		}
		if ipv4InNumericContext(data, loc[0], loc[1]) {
			continue
		}
		out = append(out, Match{Pattern: "ipv4", Value: s, Severity: "info"})
	}
	return out
}

// ipv4InNumericContext reports whether the match at data[start:end] is part of a
// longer decimal stream (SVG coordinates, version/number arrays) rather than an
// address written in isolation like `host=10.0.0.5;`. Two signals mark a stream:
//   - an adjacent '.' on the outer boundary (`38.13.44.25.57...`), which a real
//     dotted quad never has; the \b in the regex allows a '.' to sit there.
//   - a neighbouring digit separated by a single space or comma
//     (`1.11.16.2 57.17.8.2`).
func ipv4InNumericContext(data []byte, start, end int) bool {
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	if start-1 >= 0 && data[start-1] == '.' {
		return true
	}
	if end < len(data) && data[end] == '.' {
		return true
	}
	b := start - 1
	if b >= 0 && (data[b] == ' ' || data[b] == ',') {
		b--
	}
	if b >= 0 && isDigit(data[b]) {
		return true
	}
	a := end
	if a < len(data) && (data[a] == ' ' || data[a] == ',') {
		a++
	}
	if a < len(data) && isDigit(data[a]) {
		return true
	}
	return false
}

// validIPv6Match validates an IPv6 candidate. The loose regex that feeds this
// filter also matches CSS pseudo-selectors ("::before" -> "::bef") and short hex
// fragments, so a real address must parse as IPv6, not be loopback/unspecified,
// and carry at least three written hextet groups. That threshold discards the
// compressed one/two-group look-alikes while keeping documented addresses such
// as "2001:db8::1".
func validIPv6Match(s string) bool {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	groups := 0
	for _, g := range strings.Split(s, ":") {
		if g != "" {
			groups++
		}
	}
	return groups >= 3
}

// jsMemberSuffixes lists JavaScript String/Array/Object/Function/RegExp method
// and property names that commonly appear after a '.' in minified code. A
// single-segment "path" whose name ends in one of these (e.g. `/.test`,
// `/i.test`, `/.exec`) is a member-access fragment such as `re.test(x)` captured
// with a stray leading slash, not a real request path. File extensions that
// double as method names (notably `map` for source maps) are deliberately
// excluded so real assets like `/main.js.map` survive.
var jsMemberSuffixes = map[string]bool{
	"test": true, "exec": true, "call": true, "apply": true, "bind": true,
	"then": true, "catch": true, "finally": true, "join": true, "split": true,
	"match": true, "matchall": true, "replace": true, "replaceall": true,
	"slice": true, "splice": true, "substr": true, "substring": true,
	"push": true, "pop": true, "shift": true, "unshift": true, "concat": true,
	"indexof": true, "lastindexof": true, "includes": true, "foreach": true,
	"filter": true, "reduce": true, "reduceright": true, "keys": true,
	"values": true, "entries": true, "find": true, "findindex": true,
	"findlast": true, "some": true, "every": true, "sort": true, "reverse": true,
	"flat": true, "flatmap": true, "fill": true, "copywithin": true,
	"trim": true, "trimstart": true, "trimend": true, "padstart": true,
	"padend": true, "repeat": true, "normalize": true, "charat": true,
	"charcodeat": true, "codepointat": true, "startswith": true,
	"endswith": true, "tolowercase": true, "touppercase": true,
	"tostring": true, "valueof": true, "hasownproperty": true,
	"isprototypeof": true, "tofixed": true, "toprecision": true,
	"prototype": true, "constructor": true,
}

// isJSMemberFragment reports whether seg looks like a JavaScript property/method
// access (`i.test`, `.exec`) rather than a real path segment. It matches only
// when the text after the final '.' is a known member name, so genuine dotfiles
// (`.env`), assets (`app.js`) and RPC-style names (`users.list`) are preserved.
func isJSMemberFragment(seg string) bool {
	dot := strings.LastIndexByte(seg, '.')
	if dot < 0 {
		return false
	}
	return jsMemberSuffixes[strings.ToLower(seg[dot+1:])]
}

// validPathMatch validates a filesystem-path candidate from the `path` rule,
// rejecting regex/source fragments (e.g. `t:\s*([\w-]+)`) that contain quotes,
// grouping or regex escape sequences, content-free paths made only of
// underscores/slashes (`/_/_`) or single-character regex flags (`/g`, `/i`), and
// lone JS member-access fragments (`/.exec`, `/i.test`). A real path has at
// least one segment that is two or more characters and contains a letter.
func validPathMatch(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "\"'()[]{}<>*+?") {
		return false
	}
	for _, esc := range []string{`\s`, `\w`, `\d`, `\b`, `\.`, `\/`} {
		if strings.Contains(s, esc) {
			return false
		}
	}
	sep := "/"
	if strings.Contains(s, `\`) {
		sep = `\`
	}
	segs := strings.Split(s, sep)
	var nonEmpty []string
	for _, seg := range segs {
		if seg = strings.TrimSpace(seg); seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	// A path with a single segment that is a JS member-access fragment
	// (`/.exec`, `/i.test`) is minified code, not a route. Multi-segment paths
	// are left alone so real routes like `/api/test` are never dropped.
	if len(nonEmpty) == 1 && isJSMemberFragment(nonEmpty[0]) {
		return false
	}
	for _, seg := range nonEmpty {
		if len(seg) < 2 {
			continue
		}
		for i := 0; i < len(seg); i++ {
			if c := seg[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	return false
}
