package scan

import (
	"bytes"
	"regexp"
	"strings"
)

// Regular expressions to detect POST request endpoints in JavaScript.
var (
	// Optimized regex patterns with atomic groups and possessive quantifiers to prevent backtracking
	fetchPostRe   = regexp.MustCompile(`(?is)fetch\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]\s*,\s*\{([^}]*\})`)
	fetchVarRe    = regexp.MustCompile(`(?is)fetch\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)`)
	fetchBodyRe   = regexp.MustCompile(`(?is)body\s*:\s*([^,}]+)(?:,|\})`)
	fetchMethodRe = regexp.MustCompile(`(?is)method\s*:\s*['"` + "`" + `]POST['"` + "`" + `]`)

	axiosPostRe = regexp.MustCompile(`(?is)axios\.post\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `](?:\s*,\s*([^)]+))?\)`)

	jqueryPostRe = regexp.MustCompile(`(?is)\$\.post\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `](?:\s*,\s*([^)]+))?\)`)

	// More specific pattern to reduce false positives
	genericPostRe = regexp.MustCompile(`(?is)\b[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\.post\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `](?:\s*,\s*([^)]+))?\)`)

	// fetchQuest specific pattern - consider if this belongs in core patterns
	fetchQuestRe    = regexp.MustCompile(`(?is)fetchQuest\(([^,)]+)(?:,\s*([^)]*))?\)`)
	stringLiteralRe = regexp.MustCompile(`['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)

	ajaxPostObjRe = regexp.MustCompile(`(?is)\$\.ajax\s*\(\s*\{([^}]*)\}\s*\)`)
	ajaxURLRe     = regexp.MustCompile(`url\s*:\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
	ajaxMethodRe  = regexp.MustCompile(`(?is)(?:type|method)\s*:\s*['"` + "`" + `]POST['"` + "`" + `]`)
	ajaxDataRe    = regexp.MustCompile(`data\s*:\s*([^,}]+)`)
	
	// Form submission patterns
	formActionRe = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']+)["']`)
	formSubmitRe = regexp.MustCompile(`(?is)\.submit\(\)`)
	
	// API endpoint patterns - more specific to reduce false positives
	apiEndpointRe = regexp.MustCompile(`(?is)(?:/api/v[0-9]+|/v[0-9]+|/open_api)/[A-Za-z0-9_/\-]+`)

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

// extractJSExpression extracts a complete JavaScript expression (object, array, function call, etc.)
// starting at the given position in the data. It handles nested structures by counting brackets.
func extractJSExpression(data []byte, start int) string {
	if start >= len(data) {
		return ""
	}
	
	// Skip whitespace
	for start < len(data) && (data[start] == ' ' || data[start] == '\t' || data[start] == '\n' || data[start] == '\r') {
		start++
	}
	
	if start >= len(data) {
		return ""
	}
	
	openDelim := data[start]
	var closeDelim byte
	
	switch openDelim {
	case '{':
		closeDelim = '}'
	case '[':
		closeDelim = ']'
	case '(':
		closeDelim = ')'
	default:
		// Not an object/array, extract until comma or closing parenthesis
		end := start
		parenDepth := 0
		inString := false
		var stringDelim byte
		
		for end < len(data) {
			if !inString {
				if data[end] == '"' || data[end] == '\'' || data[end] == '`' {
					inString = true
					stringDelim = data[end]
				} else if data[end] == '(' {
					parenDepth++
				} else if data[end] == ')' {
					if parenDepth == 0 {
						break
					}
					parenDepth--
				} else if data[end] == ',' && parenDepth == 0 {
					break
				}
			} else {
				if data[end] == stringDelim && (end == 0 || data[end-1] != '\\') {
					inString = false
				}
			}
			end++
		}
		
		return strings.TrimSpace(string(data[start:end]))
	}
	
	// Extract nested structure
	depth := 1
	end := start + 1
	inString := false
	var stringDelim byte
	
	for end < len(data) && depth > 0 {
		if !inString {
			if data[end] == '"' || data[end] == '\'' || data[end] == '`' {
				inString = true
				stringDelim = data[end]
			} else if data[end] == openDelim {
				depth++
			} else if data[end] == closeDelim {
				depth--
			}
		} else {
			if data[end] == stringDelim && (end == 0 || data[end-1] != '\\') {
				inString = false
			}
		}
		end++
	}
	
	if depth == 0 && end <= len(data) {
		return strings.TrimSpace(string(data[start:end]))
	}
	
	return strings.TrimSpace(string(data[start:]))
}

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

	// Handle fetch with config variable
	for _, m := range fetchVarRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		varName := string(m[2])
		
		// Look for the variable definition with POST method
		varPattern := regexp.MustCompile(`(?is)(?:const|let|var)\s+` + regexp.QuoteMeta(varName) + `\s*=\s*\{([^}]*)\}`)
		if varMatch := varPattern.FindSubmatch(data); varMatch != nil {
			if fetchMethodRe.Match(varMatch[1]) {
				params := ""
				if b := fetchBodyRe.FindSubmatch(varMatch[1]); b != nil {
					params = strings.TrimSpace(string(b[1]))
				}
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
				uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
			}
		}
	}

	for _, m := range axiosPostRe.FindAllSubmatchIndex(data, -1) {
		val := string(data[m[2]:m[3]])
		params := ""
		if len(m) > 4 && m[4] != -1 {
			params = extractJSExpression(data, m[4])
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range jqueryPostRe.FindAllSubmatchIndex(data, -1) {
		val := string(data[m[2]:m[3]])
		params := ""
		if len(m) > 4 && m[4] != -1 {
			params = extractJSExpression(data, m[4])
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	for _, m := range genericPostRe.FindAllSubmatchIndex(data, -1) {
		val := string(data[m[2]:m[3]])
		params := ""
		if len(m) > 4 && m[4] != -1 {
			params = extractJSExpression(data, m[4])
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
	}

	// Handle fetchQuest pattern - appears to be a custom API wrapper
	// TODO: Consider making this pattern configurable or moving to a plugin system
	// for domain-specific patterns like /v1/q/ and /v2/q/
	for _, m := range fetchQuestRe.FindAllSubmatchIndex(data, -1) {
		arg := bytes.TrimSpace(data[m[2]:m[3]])
		params := ""
		if len(m) > 4 && m[4] != -1 {
			params = extractJSExpression(data, m[4])
		}
		val := ""
		if lit := stringLiteralRe.FindSubmatch(arg); lit != nil {
			val = string(lit[1])
		} else if idx := bytes.Index(arg, []byte("/v2/q/")); idx != -1 {
			end := idx + bytes.IndexAny(arg[idx:], "'\"`+")
			if end <= idx {
				end = len(arg)
			}
			val = string(arg[idx:end])
		} else if idx := bytes.Index(arg, []byte("/v1/q/")); idx != -1 {
			end := idx + bytes.IndexAny(arg[idx:], "'\"`+")
			if end <= idx {
				end = len(arg)
			}
			val = string(arg[idx:end])
		} else {
			val = string(arg)
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
