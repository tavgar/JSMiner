package scan

import (
	"strings"
	"testing"
)

func TestParseJSPostRequests(t *testing.T) {
	js := `fetch("https://api.example.com/v1", {method:"POST", body:send});
    axios.post('/v2/data', form);
    $.post("./local", {a:1});
    $.ajax({url:'../ajax', type:'POST', data:payload});
    var x = new XMLHttpRequest();x.open('POST', '//cdn.example.com/u');x.send(file);`
	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 5 {
		t.Fatalf("expected 5 endpoints, got %d", len(eps))
	}
	expected := map[string]struct {
		url  bool
		parm string
	}{
		"https://api.example.com/v1": {true, "send"},
		"/v2/data":                   {false, "form"},
		"./local":                    {false, "{a:1}"},
		"../ajax":                    {false, "payload"},
		"//cdn.example.com/u":        {true, "file"},
	}
	for _, e := range eps {
		ex, ok := expected[e.Value]
		if !ok {
			t.Fatalf("unexpected endpoint %s", e.Value)
		}
		if ex.url != e.IsURL || ex.parm != e.Params {
			t.Fatalf("endpoint %s mismatch", e.Value)
		}
		delete(expected, e.Value)
	}
	if len(expected) != 0 {
		t.Fatalf("missing endpoints: %v", expected)
	}
}

func TestScanReaderPostRequests(t *testing.T) {
	js := `fetch("https://ex.com/api", {method:'POST', body:req}); axios.post('/submit', data);`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderPostRequests("script.js", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	var urls, paths, params []string
	for _, m := range matches {
		switch m.Pattern {
		case "post_url":
			urls = append(urls, m.Value)
		case "post_path":
			paths = append(paths, m.Value)
		}
		params = append(params, m.Params)
	}
	if len(urls) != 1 || len(paths) != 1 || len(params) != 2 {
		t.Fatalf("unexpected counts: %d urls %d paths %d params", len(urls), len(paths), len(params))
	}
}

func TestScanReaderPostRequestsNonJS(t *testing.T) {
	js := `fetch('/ignore', {method:'POST'})`
	e := NewExtractor(true, false)
	matches, err := e.ScanReaderPostRequests("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestParseJSPostRequestsXHRComplex(t *testing.T) {
	js := `export function sendAnalytics(payload) {
  const xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://analytics.example.com/collect', true);
  xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
  xhr.send(JSON.stringify(payload));
}`
	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if !ep.IsURL || ep.Value != "https://analytics.example.com/collect" || ep.Params != "JSON.stringify(payload)" {
		t.Fatalf("unexpected endpoint %+v", ep)
	}
}

func TestParseJSPostRequestsNode(t *testing.T) {
	js := `const https = require('https');
function createOrder(order) {
  const postData = JSON.stringify(order);

  const options = {
    hostname: 'api.shop.com',
    path: '/orders',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };

  const req = https.request(options, res => {
    let data = '';
    res.on('data', chunk => (data += chunk));
    res.on('end', () => console.log('Order created:', data));
  });

  req.on('error', console.error);
  req.write(postData);
  req.end();
}`
	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if !ep.IsURL || ep.Value != "https://api.shop.com/orders" || ep.Params != "postData" {
		t.Fatalf("unexpected endpoint %+v", ep)
	}
}
func TestParseJSPostRequestsGeneric(t *testing.T) {
	js := `api.post('/send', payload); fetchQuest('https://ex.com/api', body);`
	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
	expected := map[string]string{
		"/send":              "payload",
		"https://ex.com/api": "body",
	}
	for _, ep := range eps {
		if expected[ep.Value] != ep.Params {
			t.Fatalf("unexpected %+v", ep)
		}
		delete(expected, ep.Value)
	}
	if len(expected) != 0 {
		t.Fatalf("missing endpoints %v", expected)
	}
}

func TestParseJSPostRequestsTemplateLiterals(t *testing.T) {
	js := "const endpoint = 'users';\n" +
		"const version = 'v2';\n" +
		"fetch(`/api/${version}/${endpoint}`, {\n" +
		"	method: 'POST',\n" +
		"	body: JSON.stringify(userData)\n" +
		"});\n" +
		"\n" +
		"// Dynamic endpoint with template literal\n" +
		"const id = 123;\n" +
		"axios.post(`/api/v1/users/${id}/profile`, profileData);\n" +
		"\n" +
		"// Complex nested template literal\n" +
		"const baseURL = 'https://api.example.com';\n" +
		"const resource = 'orders';\n" +
		"fetch(`${baseURL}/${resource}/${orderId}`, {\n" +
		"	method: \"POST\",\n" +
		"	body: `{\"status\": \"${newStatus}\"}`\n" +
		"});"

	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}

	// Check that template literal expressions are captured
	found := make(map[string]bool)
	for _, ep := range eps {
		if strings.Contains(ep.Value, "${") {
			found[ep.Value] = true
		}
	}

	if len(found) != 3 {
		t.Fatalf("expected 3 template literal endpoints, found %d", len(found))
	}
}

func TestParseJSPostRequestsComplexObjects(t *testing.T) {
	js := `// Complex nested object as parameter
	const config = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + token
		},
		body: JSON.stringify({
			user: {
				name: userName,
				email: userEmail,
				preferences: {
					notifications: true,
					theme: 'dark'
				}
			},
			timestamp: Date.now()
		})
	};
	fetch('/api/users', config);
	
	// Spread operator with complex object
	const baseConfig = {auth: token, version: 1};
	axios.post('/api/data', {
		...baseConfig,
		data: {
			items: items.map(i => ({id: i.id, value: i.value})),
			meta: {...metadata, processed: true}
		}
	});
	
	// Function call as parameter
	$.post('/api/transform', processData({
		input: rawData,
		options: {
			format: 'json',
			compress: true
		}
	}));`

	eps := parseJSPostRequests([]byte(js))
	if len(eps) != 3 {
		t.Logf("Endpoints found: %+v", eps)
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}

	// Verify complex parameters are captured
	hasComplexParams := false
	for _, ep := range eps {
		if strings.Contains(ep.Params, "...") || strings.Contains(ep.Params, "JSON.stringify") || strings.Contains(ep.Params, "processData") {
			hasComplexParams = true
			break
		}
	}

	if !hasComplexParams {
		t.Fatal("expected to find complex parameters with spread operator or function calls")
	}
}

func TestExtractJSExpressionEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "nested arrays and objects",
			input:    `post('/api', {data: [{id: 1, items: [1,2,3]}, {id: 2, items: [4,5,6]}]})`,
			expected: "{data: [{id: 1, items: [1,2,3]}, {id: 2, items: [4,5,6]}]}",
		},
		{
			name:     "string with escaped quotes",
			input:    `post('/api', "{\\\"key\\\": \\\"value\\\"}")`,
			expected: `"{\\\"key\\\": \\\"value\\\"}"`,
		},
		{
			name:     "function call with multiple parameters",
			input:    `post('/api', transform(data, options), callback)`,
			expected: "transform(data, options)",
		},
		{
			name:     "empty parameters",
			input:    `post('/api')`,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Extract the parameter part after the URL
			start := strings.Index(tc.input, ", ")
			if start == -1 {
				if tc.expected != "" {
					t.Fatalf("expected to find parameter, got none")
				}
				return
			}
			start += 2 // skip ", "

			result := extractJSExpression([]byte(tc.input), start)
			if result != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
