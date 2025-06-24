package scan

import (
	"regexp"
	"strings"
)

// Regular expressions to detect POST request endpoints in JavaScript.
var (
	fetchPostRe   = regexp.MustCompile("(?is)fetch\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*,\\s*({[^}]*})")
	fetchBodyRe   = regexp.MustCompile("(?is)body\\s*:\\s*([^,}]+)")
	fetchMethodRe = regexp.MustCompile("(?is)method\\s*:\\s*['\"`]POST['\"`]")

	axiosPostRe = regexp.MustCompile("(?is)axios\\.post\\(\\s*['\"`]([^'\"`]+)['\"`](?:\\s*,\\s*([^),]+))?")

	jqueryPostRe = regexp.MustCompile("(?is)\\$\\.post\\(\\s*['\"`]([^'\"`]+)['\"`](?:\\s*,\\s*([^),]+))?")

	ajaxPostObjRe = regexp.MustCompile("(?is)\\$\\.ajax\\(\\s*{([^}]*)}\\s*\\)")
	ajaxURLRe     = regexp.MustCompile("url\\s*:\\s*['\"`]([^'\"`]+)['\"`]")
	ajaxMethodRe  = regexp.MustCompile("(?is)(?:type|method)\\s*:\\s*['\"`]POST['\"`]")
	ajaxDataRe    = regexp.MustCompile("data\\s*:\\s*([^,}]+)")

	xhrPostRe = regexp.MustCompile("(?is)\\.open\\(\\s*['\"`]POST['\"`]\\s*,\\s*['\"`]([^'\"`]+)['\"`]\\).*?\\.send\\(\\s*([^);]+)")
)

// parseJSPostRequests extracts POST request endpoints from JavaScript source
// data. Returned endpoints indicate whether they are absolute URLs.
func parseJSPostRequests(data []byte) []jsEndpoint {
	uniq := make(map[string]jsEndpoint)

	for _, m := range fetchPostRe.FindAllSubmatch(data, -1) {
		opts := m[2]
		if !fetchMethodRe.Match(opts) {
			continue
		}
		params := ""
		if b := fetchBodyRe.FindSubmatch(opts); b != nil {
			params = strings.TrimSpace(string(b[1]))
		}
		val := string(m[1])
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range axiosPostRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		params := ""
		if len(m) > 2 {
			params = strings.TrimSpace(string(m[2]))
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range jqueryPostRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		params := ""
		if len(m) > 2 {
			params = strings.TrimSpace(string(m[2]))
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range ajaxPostObjRe.FindAllSubmatch(data, -1) {
		obj := m[1]
		if !ajaxMethodRe.Match(obj) {
			continue
		}
		urlMatch := ajaxURLRe.FindSubmatch(obj)
		if urlMatch == nil {
			continue
		}
		val := string(urlMatch[1])
		params := ""
		if pm := ajaxDataRe.FindSubmatch(obj); pm != nil {
			params = strings.TrimSpace(string(pm[1]))
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range xhrPostRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		params := strings.TrimSpace(string(m[2]))
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	out := make([]jsEndpoint, 0, len(uniq))
	for _, ep := range uniq {
		out = append(out, ep)
	}
	return out
}
