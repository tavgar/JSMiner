package scan

import (
	"regexp"
	"strings"
)

// Regular expressions to detect POST request endpoints in JavaScript.
var (
	fetchPostRe  = regexp.MustCompile("(?is)fetch\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*,\\s*{[^}]*?method\\s*:\\s*['\"`]POST['\"`]")
	axiosPostRe  = regexp.MustCompile("(?is)axios\\.post\\(\\s*['\"`]([^'\"`]+)['\"`]")
	jqueryPostRe = regexp.MustCompile("(?is)\\$\\.post\\(\\s*['\"`]([^'\"`]+)['\"`]")
	ajaxPostRe1  = regexp.MustCompile("(?is)\\$\\.ajax\\(\\s*{[^}]*?url\\s*:\\s*['\"`]([^'\"`]+)['\"`][^}]*?(?:type|method)\\s*:\\s*['\"`]POST['\"`]")
	ajaxPostRe2  = regexp.MustCompile("(?is)\\$\\.ajax\\(\\s*{[^}]*?(?:type|method)\\s*:\\s*['\"`]POST['\"`][^}]*?url\\s*:\\s*['\"`]([^'\"`]+)['\"`]")
	xhrPostRe    = regexp.MustCompile("(?is)\\.open\\(\\s*['\"`]POST['\"`]\\s*,\\s*['\"`]([^'\"`]+)['\"`]")
)

// parseJSPostRequests extracts POST request endpoints from JavaScript source
// data. Returned endpoints indicate whether they are absolute URLs.
func parseJSPostRequests(data []byte) []jsEndpoint {
	uniq := make(map[string]jsEndpoint)
	patterns := []*regexp.Regexp{fetchPostRe, axiosPostRe, jqueryPostRe, ajaxPostRe1, ajaxPostRe2, xhrPostRe}
	for _, re := range patterns {
		for _, m := range re.FindAllSubmatch(data, -1) {
			val := string(m[1])
			isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
			uniq[val] = jsEndpoint{Value: val, IsURL: isURL}
		}
	}
	out := make([]jsEndpoint, 0, len(uniq))
	for _, ep := range uniq {
		out = append(out, ep)
	}
	return out
}
