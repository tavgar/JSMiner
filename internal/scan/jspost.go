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

	genericPostRe = regexp.MustCompile("(?is)[A-Za-z0-9_$.]+\\.post\\(\\s*['\"`]([^'\"`]+)['\"`](?:\\s*,\\s*([^),]+))?")

	fetchQuestRe = regexp.MustCompile("(?is)fetchQuest\\(\\s*['\"`]([^'\"`]+)['\"`](?:\\s*,\\s*([^),]+))?\\)")

	ajaxPostObjRe = regexp.MustCompile("(?is)\\$\\.ajax\\(\\s*{([^}]*)}\\s*\\)")
	ajaxURLRe     = regexp.MustCompile("url\\s*:\\s*['\"`]([^'\"`]+)['\"`]")
	ajaxMethodRe  = regexp.MustCompile("(?is)(?:type|method)\\s*:\\s*['\"`]POST['\"`]")
	ajaxDataRe    = regexp.MustCompile("data\\s*:\\s*([^,}]+)")

	xhrOpenRe       = regexp.MustCompile(`(?is)([A-Za-z_\$][A-Za-z0-9_\$]*)\.open\(\s*['"]POST['"]\s*,\s*['"]([^'"]+)['"]`)
	nodeOptsRe      = regexp.MustCompile(`(?is)(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*{([^}]*)}`)
	nodeMethodRe    = regexp.MustCompile(`(?is)method\s*:\s*['"]POST['"]`)
	nodeHostRe      = regexp.MustCompile(`(?is)host(?:name)?\s*:\s*['"]([^'"]+)['"]`)
	nodePathRe      = regexp.MustCompile(`(?is)path\s*:\s*['"]([^'"]+)['"]`)
	nodeProtoRe     = regexp.MustCompile(`(?is)protocol\s*:\s*['"]([^'"]+)['"]`)
	nodeReqAssignRe = regexp.MustCompile(`(?is)(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*(https?\.request)\(\s*([A-Za-z_\$][A-Za-z0-9_\$]*)`)
	nodeInlineRe1   = regexp.MustCompile(`(?is)(https?\.request)\(\s*{([^}]*)}`)
	nodeInlineRe2   = regexp.MustCompile(`(?is)(https?\.request)\([^,]+,\s*{([^}]*)}`)
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

	for _, m := range genericPostRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		params := ""
		if len(m) > 2 {
			params = strings.TrimSpace(string(m[2]))
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range fetchQuestRe.FindAllSubmatch(data, -1) {
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

	for _, loc := range xhrOpenRe.FindAllSubmatchIndex(data, -1) {
		name := string(data[loc[2]:loc[3]])
		val := string(data[loc[4]:loc[5]])
		params := ""
		sendRe := regexp.MustCompile(regexp.QuoteMeta(name) + `\.send\(((?:[^()]+|\([^()]*\))*)\)`)
		if sm := sendRe.FindSubmatch(data[loc[1]:]); sm != nil {
			params = strings.TrimSpace(string(sm[1]))
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	// parse Node.js http/https.request patterns
	type nodeOpts struct{ host, path, proto string }
	opts := make(map[string]nodeOpts)
	for _, m := range nodeOptsRe.FindAllSubmatch(data, -1) {
		name := string(m[1])
		obj := m[2]
		if !nodeMethodRe.Match(obj) {
			continue
		}
		host := ""
		if hm := nodeHostRe.FindSubmatch(obj); hm != nil {
			host = string(hm[1])
		}
		path := ""
		if pm := nodePathRe.FindSubmatch(obj); pm != nil {
			path = string(pm[1])
		}
		proto := ""
		if pr := nodeProtoRe.FindSubmatch(obj); pr != nil {
			proto = strings.TrimSuffix(string(pr[1]), ":")
		}
		opts[name] = nodeOpts{host: host, path: path, proto: proto}
	}

	addNodeMatch := func(proto, host, path, params string) {
		val := path
		isURL := false
		if host != "" {
			isURL = true
			if proto == "" {
				proto = "https"
			}
			val = proto + "://" + host + path
		}
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, loc := range nodeReqAssignRe.FindAllSubmatchIndex(data, -1) {
		reqVar := string(data[loc[2]:loc[3]])
		schemeCall := string(data[loc[4]:loc[5]])
		optVar := string(data[loc[6]:loc[7]])
		opt, ok := opts[optVar]
		if !ok {
			continue
		}
		proto := opt.proto
		if proto == "" {
			if strings.HasPrefix(strings.ToLower(schemeCall), "http.") {
				proto = "http"
			} else {
				proto = "https"
			}
		}
		params := ""
		paramRe := regexp.MustCompile(regexp.QuoteMeta(reqVar) + `\.(?:write|end)\(([^)]*)\)`)
		if sm := paramRe.FindSubmatch(data[loc[1]:]); sm != nil {
			params = strings.TrimSpace(string(sm[1]))
		}
		addNodeMatch(proto, opt.host, opt.path, params)
	}

	for _, loc := range nodeInlineRe1.FindAllSubmatchIndex(data, -1) {
		schemeCall := string(data[loc[2]:loc[3]])
		obj := data[loc[4]:loc[5]]
		if !nodeMethodRe.Match(obj) {
			continue
		}
		host := ""
		if hm := nodeHostRe.FindSubmatch(obj); hm != nil {
			host = string(hm[1])
		}
		path := ""
		if pm := nodePathRe.FindSubmatch(obj); pm != nil {
			path = string(pm[1])
		}
		proto := "https"
		if strings.HasPrefix(strings.ToLower(schemeCall), "http.") {
			proto = "http"
		}
		addNodeMatch(proto, host, path, "")
	}

	for _, loc := range nodeInlineRe2.FindAllSubmatchIndex(data, -1) {
		schemeCall := string(data[loc[2]:loc[3]])
		obj := data[loc[4]:loc[5]]
		if !nodeMethodRe.Match(obj) {
			continue
		}
		host := ""
		if hm := nodeHostRe.FindSubmatch(obj); hm != nil {
			host = string(hm[1])
		}
		path := ""
		if pm := nodePathRe.FindSubmatch(obj); pm != nil {
			path = string(pm[1])
		}
		proto := "https"
		if strings.HasPrefix(strings.ToLower(schemeCall), "http.") {
			proto = "http"
		}
		addNodeMatch(proto, host, path, "")
	}

	out := make([]jsEndpoint, 0, len(uniq))
	for _, ep := range uniq {
		out = append(out, ep)
	}
	return out
}
