package scan

import (
	"regexp"
	"strings"
)

// endpointRe matches endpoint-like strings inside quotes or backticks. It
// captures absolute URLs, protocol-relative URLs and relative paths beginning
// with `/`, `./` or `../`.
var endpointRe = regexp.MustCompile("(?i)[\"'`](((?:https?:)?//[^\"'`\\s]+|\\.?\\.?/[^\"'`\\s]+))[\"'`]")

// jsEndpoint holds an endpoint string and whether it is an absolute URL.
// jsEndpoint holds an endpoint string, whether it is an absolute URL and any
// associated POST request parameters if available.
type jsEndpoint struct {
	Value  string
	IsURL  bool
	Params string
}

// parseJSEndpoints extracts endpoints from JavaScript source data and
// indicates whether each endpoint is an absolute URL or a relative path.
func parseJSEndpoints(data []byte) []jsEndpoint {
	ms := endpointRe.FindAllSubmatch(data, -1)
	out := make([]jsEndpoint, 0, len(ms))
	for _, m := range ms {
		val := string(m[1])
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		out = append(out, jsEndpoint{Value: val, IsURL: isURL, Params: ""})
	}
	return out
}
