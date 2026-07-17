package scan

import (
	"bytes"
	"regexp"
	"strings"
)

// This file detects HTTP headers written into source — the `headers:{…}` map of
// a fetch/axios call, an XHR `setRequestHeader`, a `new Headers({…})` — and
// reports them as `Name: value` pairs. Custom and auth headers are high-value
// recon: they reveal the API's authentication scheme and its internal/tenant
// routing conventions.
//
// The hard part is that an HTTP header and a JavaScript object entry are the
// same three tokens: `name : value`. A rule that trusts that shape reports every
// object literal, CSS declaration and HTML attribute in the bundle. Two
// observations drive the design:
//
//   - Some header names are self-evident. `Authorization`, `Referer` (the
//     misspelling is a giveaway) and anything `X-`-prefixed are not plausible as
//     ordinary object keys, so their name alone settles it.
//   - The rest are not. `age`, `date`, `host`, `origin`, `accept` and `location`
//     are registered HTTP headers *and* everyday JS keys; `{age: 30}` on a user
//     record is not a header. Nothing about the pair itself distinguishes them —
//     only whether it sits inside a header map does.
//
// So an ambiguous name is admitted only when it is enclosed by a header-map
// construct, which is established structurally (see inHeaderBlock) rather than
// by proximity: a `headers:{…}` earlier in the same minified line is not
// evidence for a pair that sits in the `body:{…}` after it.

// httpHeaderPattern names the rule in output.
const httpHeaderPattern = "http_header"

// distinctiveHeaderNames are header names that carry their own proof: no CSS
// property, HTML attribute or common object key collides with them, so a pair
// using one is reported wherever it appears. Registered names that double as
// everyday JS keys (age, date, from, host, link, range, location, origin,
// server, allow, expires, connection, vary, via, accept, expect, upgrade,
// pragma, trailer, warning) are deliberately absent — they are admitted only
// inside a header map. `X-`-prefixed headers are covered by shape in
// isCustomHeaderName and are likewise not listed here.
var distinctiveHeaderNames = map[string]bool{
	// Authentication and authorization.
	"authorization": true, "proxy-authorization": true,
	"www-authenticate": true, "proxy-authenticate": true,

	// Content description and negotiation.
	"content-type": true, "content-length": true, "content-encoding": true,
	"content-disposition": true, "content-language": true, "content-range": true,
	"content-location": true, "content-md5": true, "accept-encoding": true,
	"accept-language": true, "accept-charset": true, "accept-ranges": true,
	"accept-patch": true,

	// Caching and conditional requests.
	"cache-control": true, "if-match": true, "if-none-match": true,
	"if-modified-since": true, "if-unmodified-since": true, "if-range": true,
	"last-modified": true, "retry-after": true, "etag": true,

	// Cookies, identity and transport.
	"set-cookie": true, "cookie": true, "user-agent": true, "referer": true,
	"transfer-encoding": true, "keep-alive": true, "proxy-connection": true,
	"max-forwards": true, "dnt": true,

	// Security response headers.
	"content-security-policy": true, "content-security-policy-report-only": true,
	"strict-transport-security": true, "referrer-policy": true,
	"permissions-policy": true, "feature-policy": true, "expect-ct": true,
	"upgrade-insecure-requests": true, "cross-origin-opener-policy": true,
	"cross-origin-embedder-policy": true, "cross-origin-resource-policy": true,

	// CORS.
	"access-control-allow-origin": true, "access-control-allow-methods": true,
	"access-control-allow-headers": true, "access-control-allow-credentials": true,
	"access-control-expose-headers": true, "access-control-max-age": true,
	"access-control-request-method": true, "access-control-request-headers": true,

	// Fetch metadata.
	"sec-fetch-mode": true, "sec-fetch-site": true, "sec-fetch-dest": true,
	"sec-fetch-user": true, "sec-websocket-key": true, "sec-websocket-accept": true,
	"sec-websocket-version": true, "sec-websocket-protocol": true,
}

// customHeaderShapeRE matches the `X-` convention for non-standard headers
// (`X-Api-Key`, `X-Tenant-Id`, `X-Amz-Security-Token`). No CSS property and no
// standard HTML attribute uses this shape, so it needs no surrounding context.
var customHeaderShapeRE = regexp.MustCompile(`^x-[a-z0-9]+(?:-[a-z0-9]+)*$`)

// nonHeaderXNames are `x-`-shaped tokens that are not HTTP headers. The `X-`
// convention is otherwise strong enough to stand without context, so the
// exceptions are enumerated rather than guessed at:
//
//   - Alpine.js directives, which appear as `x-`-prefixed attributes throughout
//     markup and framework code.
//   - The `x-`-prefixed labels of the WHATWG Encoding Standard, a closed set
//     that ships as a label→encoding lookup table (`{"x-cp1250":"windows-1250"}`)
//     in whatwg-encoding, iconv-lite and every bundle that depends on them. The
//     table is shaped exactly like a header map, so only the names identify it.
//   - The CSS `x-small`/`x-large` font keywords.
var nonHeaderXNames = map[string]bool{
	// Alpine.js directives.
	"x-data": true, "x-show": true, "x-model": true, "x-modelable": true,
	"x-on": true, "x-bind": true, "x-if": true, "x-for": true, "x-text": true,
	"x-html": true, "x-init": true, "x-ref": true, "x-cloak": true,
	"x-effect": true, "x-ignore": true, "x-teleport": true, "x-spread": true,
	"x-transition": true,

	// WHATWG Encoding Standard labels.
	"x-cp1250": true, "x-cp1251": true, "x-cp1252": true, "x-cp1253": true,
	"x-cp1254": true, "x-cp1255": true, "x-cp1256": true, "x-cp1257": true,
	"x-cp1258": true, "x-mac-cyrillic": true, "x-mac-roman": true,
	"x-mac-ukrainian": true, "x-euc-jp": true, "x-sjis": true, "x-gbk": true,
	"x-big5": true, "x-x-big5": true, "x-user-defined": true,
	"x-unicode20utf8": true, "x-obsolete": true,

	// CSS font-size keywords.
	"x-small": true, "x-large": true, "x-height": true, "x-axis": true,
}

// minCustomHeaderLen keeps the `X-` shape from admitting stubs like `x-y`. Every
// real custom header clears it; `x-id` (also an Alpine directive) does not, and
// is not worth the ambiguity.
const minCustomHeaderLen = 5

// isCustomHeaderName reports whether lower (an already-lowercased name) follows
// the `X-` custom-header convention and is not a known non-header `x-` token.
func isCustomHeaderName(lower string) bool {
	if len(lower) < minCustomHeaderLen || nonHeaderXNames[lower] {
		return false
	}
	return customHeaderShapeRE.MatchString(lower)
}

// headerName matches a name in RFC 9110's practical charset. The 3-character
// floor drops the `e:t` noise that dominates minified object literals before any
// further work; the shortest names it costs us (`te`) are ambiguous ones that
// would need a header map to be admitted anyway.
const headerName = `([a-z][a-z0-9-]{2,62})`

// headerValue matches a quoted, template or bare value. Quoted alternatives come
// first so a full string literal wins over its prefix, and the bare alternative
// excludes the separators and brackets that end a value, so neighbouring code
// (`,age:30}`) cannot leak into it. A bare value additionally may not open with
// `=`: that only happens when an `=` separator has landed on the first half of a
// `==` comparison (`headers["content-type"]==null`), which reads a header rather
// than setting one and carries no value worth reporting.
const headerValue = "(\"[^\"\\r\\n]{1,256}\"|'[^'\\r\\n]{1,256}'|`[^`\\r\\n]{1,256}`|[^\\s,;{}()\\[\\]\"'`=][^\\s,;{}()\\[\\]\"'`]{0,255})"

// headerPairRE matches the `name: value` form: an object entry
// (`{"X-Api-Key":"k"}`, `{Authorization:`Bearer ${t}`}`) or a raw header line
// inside a string. Quotes around the name are optional and matched loosely
// rather than balanced, since RE2 has no backreferences and the name registry,
// not the quoting, is what decides the match.
var headerPairRE = regexp.MustCompile(`(?i)["'` + "`" + `]?\b` + headerName + `["'` + "`" + `]?\s*:\s*` + headerValue)

// headerRawRE matches a whole header line written inside one string literal
// (`"Authorization: Bearer sk_live_…\r\n"`), where the name is not separately
// quoted. headerPairRE also reaches these but mistakes the opening quote for the
// name's own and truncates the value at the first space; this alternative keeps
// the value whole. Overlap between the two is removed by the dedup in Find.
var headerRawRE = regexp.MustCompile(`(?i)["'` + "`" + `]` + headerName + `:[ \t]*([^"'` + "`" + `\r\n]{1,256})["'` + "`" + `]`)

// headerSetCallRE matches a call that exists to set a header: XHR's
// `setRequestHeader("X","Y")`, Node/ethers' `setHeader("X","Y")`, and `.set`/
// `.append`/`.add` on a receiver literally named `headers`. The callee names the
// intent, so the first argument is a header name whatever it is.
var headerSetCallRE = regexp.MustCompile(`(?i)(?:set(?:Request)?Header|headers\s*\.\s*(?:set|append|add))\s*\(\s*["'` + "`" + `]` + headerName + `["'` + "`" + `]\s*,\s*` + headerValue)

// headerMemberCallRE matches `.set(…)`/`.append(…)` on any receiver, which is
// how a minified bundle emits a Headers/axios call once the variable is mangled
// (`h.set("X-Api-Key",k)`). The callee proves nothing on its own — it equally
// fits `cache.set("user","alice")` — so only a self-identifying name is admitted
// through this form.
var headerMemberCallRE = regexp.MustCompile(`(?i)\.\s*(?:set|append)\s*\(\s*["'` + "`" + `]` + headerName + `["'` + "`" + `]\s*,\s*` + headerValue)

// headerIndexRE matches assignment into a header map by key —
// `headers["content-type"]="application/json"`, `req.headers['authorization']=t`,
// axios' `headers.common['X-Api-Key']=k` — which neither the object-literal nor
// the call form reaches. A literal `headers` receiver is required: `=` is far too
// common a separator to admit on the name's shape alone (`x-data="…"` in markup,
// `X-Amz-Signature=…` in a presigned query string), and the receiver is what
// makes it unambiguous.
var headerIndexRE = regexp.MustCompile(`(?i)headers\s*(?:\.\s*[a-z]+\s*)?\[\s*["'` + "`" + `]` + headerName + `["'` + "`" + `]\s*\]\s*=\s*` + headerValue)

// headerBlockAnchorRE matches the constructs that open an object literal whose
// entries are HTTP headers: `headers:{…}`, `headers = {…}`, `new Headers({…})`.
//
// Three properties of this pattern are load-bearing, each earned from a real
// bundle:
//
//   - It includes the `{` it opens, so the anchor means "a header map starts
//     here" rather than "the word headers appears nearby". Mentioning the stem is
//     not enough: in `this.headers=o,…,axios.create({baseURL:e,timeout:t})` an
//     unrelated assignment would otherwise anchor the config object after it, and
//     `Object.defineProperties(Headers.prototype,{…})` would anchor a property
//     descriptor.
//   - It admits only object literals, never calls. A call takes comma-separated
//     arguments, so no `name: value` pair inside one is an entry of it — in
//     socket.io's `setHeader("Content-Type","application/"+(isMap?"json":
//     "javascript"))` the ternary's `"json" : "javascript"` sits inside the
//     parens but is an expression. Header-setting calls are matched directly by
//     headerSetCallRE instead, which takes the name from the first argument.
//   - The stem carries no leading word boundary, so the usual wrappers
//     (`requestHeaders`, `defaultHeaders`, `extraHeaders`) anchor too. The
//     singular `header` is excluded on purpose: `header:{title:"…"}` is a common
//     UI config.
var headerBlockAnchorRE = regexp.MustCompile(`(?i)headers\s*[:=]\s*\{|headers\s*\(\s*\{`)

// nonHeaderNames never name an HTTP header, yet appear as keys of a block that a
// header map is otherwise indistinguishable from. The JS property descriptor is
// the case that matters: node-fetch and prisma ship
// `Object.defineProperties(Request.prototype,{headers:{enumerable:!0}})`, which
// opens a genuine `headers:{…}` literal whose entries are descriptor keys.
var nonHeaderNames = map[string]bool{
	"enumerable": true, "configurable": true, "writable": true, "value": true,
	"get": true, "set": true, "prototype": true, "constructor": true,
	"__proto__": true,
}

// headerForm pairs a syntactic form with what that syntax proves about the name
// it captures. The three tiers are the whole precision story of this rule.
type headerForm struct {
	re *regexp.Regexp

	// selfAnchored marks a form whose own syntax establishes that a header is
	// being set: `setRequestHeader("Accept",…)` and `headers["age"]=…` name the
	// header map outright, so the captured name is a header whatever it is.
	selfAnchored bool

	// blockScoped marks the bare `name: value` pair, which in isolation is
	// indistinguishable from any object entry. A name that does not identify
	// itself is admitted only when a header map literal encloses it.
	blockScoped bool

	// A form that is neither admits only self-identifying names — a distinctive
	// registry entry or the `X-` shape.
}

var headerForms = []headerForm{
	// Raw first: a header line inside a string satisfies headerPairRE too, but
	// truncates there, and the dedup in Find keeps whichever pair is seen first.
	{re: headerRawRE, blockScoped: true},
	{re: headerPairRE, blockScoped: true},
	{re: headerSetCallRE, selfAnchored: true},
	{re: headerIndexRE, selfAnchored: true},
	{re: headerMemberCallRE},
}

// headerContextWindow bounds the lookback for an anchor. Minified bundles arrive
// as one multi-MB line, so the search must be capped; 256 bytes spans a densely
// packed header map without scanning unrelated code.
//
// Rules are handed one line at a time, which bounds this rule's reach: in
// pretty-printed source an ambiguous name on its own line cannot see the
// `headers:{` that opened the block above it, so `Accept: "application/json"`
// there is not reported. The gap is narrow and falls on the safe side. Minified
// bundles — the input this rule is aimed at, and the one where the look-alikes
// are dense — are a single line, so their maps resolve in full; self-identifying
// names (`Authorization`, `Content-Type`, `X-…`) need no context at any
// formatting; and header-setting calls carry their anchor on the same line.
const headerContextWindow = 256

// httpHeaderRule detects HTTP headers in source while rejecting the object
// literals, CSS declarations and framework directives that share the
// `name: value` shape. The decision needs the bytes around a hit, so this is a
// dedicated Rule rather than a regex plus a value filter.
type httpHeaderRule struct{}

func newHTTPHeaderRule() httpHeaderRule { return httpHeaderRule{} }

func (httpHeaderRule) MatchName() string { return httpHeaderPattern }

func (httpHeaderRule) Find(data []byte) []Match {
	// Every supported header spelling necessarily contains one of these syntax
	// bytes: ':' for pair/raw forms, '(' for setter calls, or '[' for indexed
	// assignment. Most lines of pretty-printed source contain none of them. Reject
	// those lines before running five regex engines over the same bytes; this is
	// an exact syntactic prerequisite, so it cannot suppress a possible match.
	if bytes.IndexByte(data, ':') < 0 &&
		bytes.IndexByte(data, '(') < 0 &&
		bytes.IndexByte(data, '[') < 0 {
		return nil
	}

	var out []Match
	// The forms overlap — `headers.set("X","Y")` satisfies both call forms — so
	// identical pairs are reported once.
	seen := make(map[string]bool)
	for _, f := range headerForms {
		for _, m := range f.re.FindAllSubmatchIndex(data, -1) {
			// The name's own offset is the context position: a match may start
			// before the enclosing map's `{`, and looking back from the match start
			// would then miss the anchor.
			nameStart := m[2]
			name := string(data[m[2]:m[3]])
			if !acceptHeaderName(name, data, nameStart, f) {
				continue
			}
			val := cleanHeaderValue(string(data[m[4]:m[5]]))
			if val == "" {
				continue
			}
			pair := name + ": " + val
			if seen[pair] {
				continue
			}
			seen[pair] = true
			out = append(out, Match{
				Pattern:  httpHeaderPattern,
				Value:    pair,
				Severity: SeverityMedium,
			})
		}
	}
	return out
}

// acceptHeaderName decides whether the pair captured by form, whose name starts
// at nameStart, is an HTTP header. The form's syntax is consulted first: when it
// already proves a header is being set, the name needs no further evidence.
// Otherwise a distinctive name or the `X-` shape settles it alone, and every
// other name — a registered-but-ambiguous one like `age`, or a custom one like
// `apikey` — is a header only inside a header map, where by construction every
// entry is one.
func acceptHeaderName(name string, data []byte, nameStart int, form headerForm) bool {
	lower := strings.ToLower(name)
	if nonHeaderNames[lower] {
		return false
	}
	if form.selfAnchored {
		return true
	}
	if distinctiveHeaderNames[lower] || isCustomHeaderName(lower) {
		return true
	}
	return form.blockScoped && inHeaderBlock(data, nameStart)
}

// inHeaderBlock reports whether the name at nameStart is enclosed by the nearest
// preceding header map literal. Proximity alone is not enough: in
// `fetch(u,{headers:{Accept:"x"},body:{age:30}})` the `age` pair is well within
// the window of `headers:{` but sits in a sibling object. So the bytes from the
// anchor to the name are walked with a bracket depth, and the block must still
// be open when the name is reached.
func inHeaderBlock(data []byte, nameStart int) bool {
	from := nameStart - headerContextWindow
	if from < 0 {
		from = 0
	}
	anchors := headerBlockAnchorRE.FindAllIndex(data[from:nameStart], -1)
	if len(anchors) == 0 {
		return false
	}
	nearest := anchors[len(anchors)-1]
	span := data[from+nearest[1] : nameStart]
	// A quoted name (`setRequestHeader("Accept"`, `headers:{"Accept"`) leaves its
	// own opening quote as the span's last byte. That quote opens the string the
	// name sits in, so walking it as a literal to skip would run off the end.
	return blockStillOpen(bytes.TrimRight(span, "\"'`"))
}

// blockStillOpen walks span — the bytes between a header anchor's opening
// bracket and the candidate name — and reports whether that block is still open
// when the name is reached. Depth starts at 1 for the anchor's own bracket, so
// dropping to 0 means the header map closed and the name belongs to whatever
// followed it. String literals are skipped so punctuation inside a value (`{`,
// `)`) does not disturb the count.
func blockStillOpen(span []byte) bool {
	depth := 1
	for i := 0; i < len(span); i++ {
		switch c := span[i]; c {
		case '"', '\'', '`':
			// Skip to the closing quote, honouring backslash escapes. An unterminated
			// literal means the span was cut mid-string by the window, in which case
			// there is no reliable depth to report.
			for i++; i < len(span); i++ {
				if span[i] == '\\' {
					i++
					continue
				}
				if span[i] == c {
					break
				}
			}
			if i >= len(span) {
				return false
			}
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			if depth--; depth <= 0 {
				return false
			}
		}
	}
	return true
}

// cleanHeaderValue strips the quoting and the trailing CRLF escape that a raw
// header line inside a string literal carries (`"Accept: */*\r\n"`), leaving the
// value as it would appear on the wire.
func cleanHeaderValue(v string) string {
	v = strings.Trim(strings.TrimSpace(v), "\"'`")
	v = strings.TrimSpace(v)
	for _, esc := range []string{`\r\n`, `\n`, `\r`} {
		v = strings.TrimSuffix(v, esc)
	}
	return strings.TrimSpace(v)
}
