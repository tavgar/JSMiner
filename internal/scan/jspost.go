package scan

import (
	"bytes"
	"regexp"
	"strings"
)

// inferAuthParams infers common parameters based on endpoint patterns
func inferAuthParams(endpoint string) string {
	endpoint = strings.ToLower(endpoint)

	// Common authentication endpoints and their typical parameters
	if strings.Contains(endpoint, "idm") || strings.Contains(endpoint, "identity") {
		return "phone, password, code (OTP)"
	}
	if strings.Contains(endpoint, "3p") || strings.Contains(endpoint, "third-party") {
		return "app_secret, callback, environment"
	}
	if strings.Contains(endpoint, "oauth") || strings.Contains(endpoint, "authorize") {
		return "client_id, redirect_uri, response_type, scope"
	}
	if strings.Contains(endpoint, "token") {
		return "grant_type, code, client_id, client_secret"
	}
	if strings.Contains(endpoint, "login") || strings.Contains(endpoint, "signin") || strings.Contains(endpoint, "authenticate") {
		return "username/email, password"
	}
	if strings.Contains(endpoint, "register") || strings.Contains(endpoint, "signup") {
		return "email, password, name, phone"
	}
	if strings.Contains(endpoint, "verify") {
		return "code, token"
	}
	if strings.Contains(endpoint, "forgot") || strings.Contains(endpoint, "reset") {
		return "email/phone, token, new_password"
	}

	return ""
}

// extractAuthParams looks for common authentication parameters in the given context
func extractAuthParams(context []byte) string {
	// Common auth parameter patterns
	paramPatterns := map[string]*regexp.Regexp{
		"email":    regexp.MustCompile(`(?i)(?:email|mail|user(?:name)?)\s*:\s*[^,}]+`),
		"password": regexp.MustCompile(`(?i)(?:password|pass(?:word)?|pwd)\s*:\s*[^,}]+`),
		"username": regexp.MustCompile(`(?i)(?:username|user)\s*:\s*[^,}]+`),
		"token":    regexp.MustCompile(`(?i)(?:token|csrf|authenticity_token)\s*:\s*[^,}]+`),
	}

	foundParams := []string{}
	contextStr := string(context)

	// Look for object notation parameters
	objectPattern := regexp.MustCompile(`\{([^}]*(?:email|username|password|token)[^}]*)\}`)
	if matches := objectPattern.FindStringSubmatch(contextStr); len(matches) > 1 {
		// Extract individual parameters
		for paramName, pattern := range paramPatterns {
			if pattern.MatchString(matches[1]) {
				foundParams = append(foundParams, paramName)
			}
		}
	}

	// Look for FormData append patterns
	formDataPattern := regexp.MustCompile(`\.append\s*\(\s*['"](\w+)['"]`)
	if matches := formDataPattern.FindAllStringSubmatch(contextStr, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				param := match[1]
				// Check if it's a common auth param
				if strings.Contains("email username password token user pass", strings.ToLower(param)) {
					foundParams = append(foundParams, param)
				}
			}
		}
	}

	// Look for input field patterns
	inputPattern := regexp.MustCompile(`(?i)(?:name|id)\s*=\s*["'](\w+)["'].*?type\s*=\s*["'](password|email|text)["']`)
	if matches := inputPattern.FindAllStringSubmatch(contextStr, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) > 1 {
				foundParams = append(foundParams, match[1])
			}
		}
	}

	if len(foundParams) > 0 {
		// Remove duplicates
		seen := make(map[string]bool)
		unique := []string{}
		for _, param := range foundParams {
			if !seen[param] {
				seen[param] = true
				unique = append(unique, param)
			}
		}
		return "inferred: " + strings.Join(unique, ", ")
	}

	return ""
}

// Regular expressions to detect POST request endpoints in JavaScript.
var (
	// Optimized regex patterns with atomic groups and possessive quantifiers to prevent backtracking
	fetchPostRe   = regexp.MustCompile(`(?is)fetch\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]\s*,\s*\{([^}]*\})`)
	fetchVarRe    = regexp.MustCompile(`(?is)fetch\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)`)
	fetchBodyRe   = regexp.MustCompile(`(?is)body\s*:\s*([^,}]+)(?:,|\})`)
	fetchMethodRe = regexp.MustCompile(`(?is)method\s*:\s*['"` + "`" + `]POST['"` + "`" + `]`)
	// Also match method with variable or uppercase POST
	fetchMethodVarRe = regexp.MustCompile(`(?is)method\s*:\s*(?:['"` + "`" + `]?POST['"` + "`" + `]?|[A-Za-z_$][A-Za-z0-9_$]*)`)

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

	// Modern framework patterns
	// React/Next.js form submission patterns
	onSubmitRe     = regexp.MustCompile(`(?is)onSubmit\s*[:=]\s*(?:async\s+)?(?:function\s*\([^)]*\)|(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>)`)
	handleSubmitRe = regexp.MustCompile(`(?is)(?:handle|on)(?:Submit|Login|SignIn|Auth)\s*[:=]\s*(?:async\s+)?(?:function\s*\([^)]*\)|(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>)`)

	// GraphQL mutation patterns
	graphqlMutationRe = regexp.MustCompile(`(?is)mutation\s+(?:login|signin|authenticate|auth)[^{]*\{`)

	// Auth library patterns (NextAuth, Auth0, etc.)
	signInRe = regexp.MustCompile(`(?is)signIn\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `](?:\s*,\s*([^)]+))?\)`)

	// API route patterns
	apiRouteRe     = regexp.MustCompile(`(?is)['"` + "`" + `](/api/[A-Za-z0-9_/\-]+)['"` + "`" + `]`)
	authEndpointRe = regexp.MustCompile(`(?is)['"` + "`" + `](/(?:auth|login|signin|sign-in|authenticate|account/sign-in|api/idm|api/hyper-document)[A-Za-z0-9_/\-]*)['"` + "`" + `]`)

	// Form event patterns
	preventDefaultRe = regexp.MustCompile(`(?is)(?:event|e)\.preventDefault\s*\(\s*\)`)

	// Next.js API routes with dynamic segments
	nextAPIRouteRe = regexp.MustCompile(`(?is)['"` + "`" + `](/api/auth/[A-Za-z0-9_/\-\[\]]+)['"` + "`" + `]`)

	xhrOpenRe       = regexp.MustCompile(`(?is)([A-Za-z_\$][A-Za-z0-9_\$]*)\.open\(\s*['"]POST['"]\s*,\s*['"]([^'"]+)['"]`)
	nodeOptsRe      = regexp.MustCompile(`(?is)(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*{([^}]*)}`)
	nodeMethodRe    = regexp.MustCompile(`(?is)method\s*:\s*['"]POST['"]`)
	nodeHostRe      = regexp.MustCompile(`(?is)host(?:name)?\s*:\s*['"]([^'"]+)['"]`)
	nodePathRe      = regexp.MustCompile(`(?is)path\s*:\s*['"]([^'"]+)['"]`)
	nodeProtoRe     = regexp.MustCompile(`(?is)protocol\s*:\s*['"]([^'"]+)['"]`)
	nodeReqAssignRe = regexp.MustCompile(`(?is)(?:const|let|var)\s+([A-Za-z_\$][A-Za-z0-9_\$]*)\s*=\s*(https?\.request)\(\s*([A-Za-z_\$][A-Za-z0-9_\$]*)`)
	nodeInlineRe1   = regexp.MustCompile(`(?is)(https?\.request)\(\s*{([^}]*)}`)
	// Simplified: matches http(s).request with first arg and options object
	nodeInlineRe2 = regexp.MustCompile(`(?is)(https?\.request)\(([^,]+),\s*\{([^}]*)\}`)
)

// isEscaped checks if the character at position pos is escaped by counting preceding backslashes
func isEscaped(data []byte, pos int) bool {
	if pos == 0 {
		return false
	}
	backslashCount := 0
	for i := pos - 1; i >= 0 && data[i] == '\\'; i-- {
		backslashCount++
	}
	// Character is escaped if there's an odd number of backslashes
	return backslashCount%2 == 1
}

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
				if data[end] == stringDelim && !isEscaped(data, end) {
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
		// If no params found, look for common authentication parameters in the surrounding context
		if params == "" {
			contextStart := bytes.Index(data, m[0]) - 500
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := bytes.Index(data, m[0]) + len(m[0]) + 500
			if contextEnd > len(data) {
				contextEnd = len(data)
			}
			context := data[contextStart:contextEnd]
			params = extractAuthParams(context)
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
		} else {
			// Check for configurable patterns
			fetchQuestPatterns := []string{"/v1/q/", "/v2/q/", "/api/q/", "/quest/"}
			for _, pattern := range fetchQuestPatterns {
				if idx := bytes.Index(arg, []byte(pattern)); idx != -1 {
					end := idx + bytes.IndexAny(arg[idx:], "'\"`+")
					if end <= idx {
						end = len(arg)
					}
					val = string(arg[idx:end])
					break
				}
			}
		}
		if val == "" {
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
		// Skip first argument (loc[4]:loc[5])
		obj := data[loc[6]:loc[7]]
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

	// Handle modern framework patterns
	// Look for form submission handlers that likely contain POST requests
	if onSubmitRe.Match(data) || handleSubmitRe.Match(data) || preventDefaultRe.Match(data) {
		// Search for fetch/axios/ajax calls within the file that might be in submit handlers
		// Also look for common auth endpoints
		for _, m := range authEndpointRe.FindAllSubmatch(data, -1) {
			val := string(m[1])
			isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
			// Infer parameters based on endpoint type
			params := inferAuthParams(val)
			uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
		}

		// Look for API routes that might be used for authentication
		for _, m := range apiRouteRe.FindAllSubmatch(data, -1) {
			val := string(m[1])
			// Filter for likely auth-related endpoints
			if strings.Contains(strings.ToLower(val), "auth") ||
				strings.Contains(strings.ToLower(val), "login") ||
				strings.Contains(strings.ToLower(val), "signin") ||
				strings.Contains(strings.ToLower(val), "sign-in") {
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
				// Infer parameters based on endpoint type
				params := inferAuthParams(val)
				uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
			}
		}

		// Look for Next.js API routes
		for _, m := range nextAPIRouteRe.FindAllSubmatch(data, -1) {
			val := string(m[1])
			isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
			params := inferAuthParams(val)
			uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
		}
	}

	// Additional patterns for async/dynamic requests
	// Look for any API endpoint that might handle POST
	for _, m := range apiRouteRe.FindAllSubmatch(data, -1) {
		val := string(m[1])
		// Check if there's any POST-related code nearby
		startIdx := bytes.Index(data, m[0])
		if startIdx == -1 {
			continue
		}
		contextStart := startIdx - 500
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := startIdx + 500
		if contextEnd > len(data) {
			contextEnd = len(data)
		}
		context := data[contextStart:contextEnd]

		// If POST is mentioned in nearby context, include this endpoint
		if bytes.Contains(bytes.ToLower(context), []byte("post")) ||
			bytes.Contains(bytes.ToLower(context), []byte("method")) ||
			bytes.Contains(context, []byte("body:")) ||
			bytes.Contains(context, []byte("data:")) {
			isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
			params := inferAuthParams(val)
			uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
		}
	}

	// Handle NextAuth/Auth0 signIn patterns
	for _, m := range signInRe.FindAllSubmatchIndex(data, -1) {
		val := string(data[m[2]:m[3]])
		params := ""
		if len(m) > 4 && m[4] != -1 {
			params = extractJSExpression(data, m[4])
		}
		// signIn often uses provider names, but we should also check for endpoints
		if strings.HasPrefix(val, "/") || strings.HasPrefix(val, "http") {
			isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
			uniq[val+"|"+params] = jsEndpoint{Value: val, IsURL: isURL, Params: params}
		}
	}

	// Look for GraphQL mutations
	if graphqlMutationRe.Match(data) {
		// Common GraphQL endpoints
		graphqlEndpoints := []string{"/graphql", "/api/graphql", "/gql"}
		for _, endpoint := range graphqlEndpoints {
			// Check if this endpoint appears in the file
			if strings.Contains(string(data), endpoint) {
				params := "query, variables, operationName"
				uniq[endpoint+"|"+params] = jsEndpoint{Value: endpoint, IsURL: false, Params: params}
			}
		}
	}

	// convert map to slice of unique endpoint+params combinations
	out := make([]jsEndpoint, 0, len(uniq))
	for _, ep := range uniq {
		out = append(out, ep)
	}
	return out
}
