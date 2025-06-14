package scan

import "regexp"

// endpointRe matches endpoint-like strings inside quotes or backticks. It
// captures absolute URLs, protocol-relative URLs and relative paths beginning
// with `/`, `./` or `../`.
var endpointRe = regexp.MustCompile("(?i)[\"'`](((?:https?:)?//[^\"'`\\s]+|\\.?\\.?/[^\"'`\\s]+))[\"'`]")

// parseJSEndpoints extracts endpoints from JavaScript source data.
func parseJSEndpoints(data []byte) []string {
	ms := endpointRe.FindAllSubmatch(data, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m[1]))
	}
	return out
}
