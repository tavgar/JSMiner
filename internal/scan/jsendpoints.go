package scan

import (
	"regexp"
	"strings"
)

// endpointRe matches endpoint-like strings inside quotes or backticks. It
// captures absolute URLs, protocol-relative URLs and relative paths beginning
// with `/`, `./` or `../`.
// Updated regex: allow any number of `${...}` interpolation segments before the actual
// endpoint so that template literals like `${base}/api/login` are matched. We keep the
// core capture group (the endpoint) unchanged to preserve downstream behaviour.
// The optional non-capturing prefix `(?:\$\{[^}]+\})*` consumes one or more interpolation
// segments without including them in the final capture value. The scheme group
// accepts http(s) and ws(s) so WebSocket endpoints are captured too.
var endpointRe = regexp.MustCompile("(?i)[\"'`](?:\\$\\{[^}]+\\})*((?:(?:https?|wss?):)?//[^\"'`\\s]+|\\.?\\.?/[^\"'`\\s]+)[\"'`]")

// bareRelEndpointRe captures bare relative request paths that lack a leading
// slash — e.g. fetch("api/users"), axios.post("v3/orders", body),
// xhr.open("GET", ...) style callers. Matching these unconditionally would be
// far too noisy (every "text/html", "16/9" or "en/US" would qualify), so the
// pattern is anchored to a request-issuing call and the captured path must
// contain at least one `/` segment. That context requirement is what keeps the
// added recall from costing precision.
//
// A trailing `(?:[?#][^"'`]*)?` lets an optional query string or fragment sit
// between the path and the closing quote, so a concatenated call like
// fetch("api/search?q=" + q) still yields the crawlable path "api/search"; the
// query is consumed but left out of the capture because its dynamic tail is
// incomplete anyway.
var bareRelEndpointRe = regexp.MustCompile("(?i)(?:\\bfetch|\\baxios(?:\\.\\w+)?|\\$\\.(?:ajax|get|post)|\\.(?:get|post|put|patch|delete|open|request|ajax))\\s*\\(\\s*[\"'`]([a-z0-9_][a-z0-9_.-]*(?:/[a-z0-9_.-]+)+)(?:[?#][^\"'`]*)?[\"'`]")

// wsEventSourceRe captures the URL argument of a WebSocket or EventSource
// constructor — new WebSocket("wss://…"), new WebSocket("realtime/feed"),
// EventSource("/stream"), new EventSource("events"). Absolute ws(s):// URLs and
// rooted paths are already caught by endpointRe, but the bare-relative forms are
// not (bareRelEndpointRe only fires in fetch/axios/XHR call context), and real-time
// endpoints are exactly the kind of surface a secret scan wants surfaced. Matching
// the constructor makes the capture precise, so it does not add noise.
var wsEventSourceRe = regexp.MustCompile("(?i)(?:new\\s+)?(?:WebSocket|EventSource)\\s*\\(\\s*[\"'`]((?:\\$\\{[^}]+\\})*[^\"'`\\s]+)[\"'`]")

// jsEndpoint holds an endpoint string and whether it is an absolute URL.
// jsEndpoint holds an endpoint string, whether it is an absolute URL and any
// associated POST request parameters if available.
type jsEndpoint struct {
	Value  string
	IsURL  bool
	Params string
}

// isAbsoluteEndpoint reports whether val is an absolute or protocol-relative URL
// (as opposed to a rooted or relative path).
func isAbsoluteEndpoint(val string) bool {
	return strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") ||
		strings.HasPrefix(val, "ws://") || strings.HasPrefix(val, "wss://") ||
		strings.HasPrefix(val, "//")
}

// trimInterpolation reduces a captured endpoint to the static portion before its
// first `${...}` template interpolation. A path like `/api/user/${id}/posts`
// becomes `/api/user/` — the crawlable base — instead of being discarded for
// containing `${}` metacharacters. Values with no interpolation are unchanged.
func trimInterpolation(val string) string {
	if i := strings.Index(val, "${"); i >= 0 {
		return val[:i]
	}
	return val
}

// parseJSEndpoints extracts endpoints from JavaScript source data and
// indicates whether each endpoint is an absolute URL or a relative path.
func parseJSEndpoints(data []byte) []jsEndpoint {
	out := make([]jsEndpoint, 0)
	seen := make(map[string]struct{})
	add := func(val string, isURL bool) {
		val = trimInterpolation(val)
		if val == "" {
			return
		}
		if _, ok := seen[val]; ok {
			return
		}
		seen[val] = struct{}{}
		out = append(out, jsEndpoint{Value: val, IsURL: isURL})
	}
	for _, m := range endpointRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		add(val, isAbsoluteEndpoint(val))
	}
	// Bare relative request paths (no leading slash), only in request-call context.
	for _, m := range bareRelEndpointRe.FindAllSubmatch(data, -1) {
		add(string(m[1]), false)
	}
	// WebSocket / EventSource (SSE) endpoints, including bare-relative forms.
	for _, m := range wsEventSourceRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		add(val, isAbsoluteEndpoint(val))
	}
	return out
}
