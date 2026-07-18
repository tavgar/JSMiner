package scan

import (
	"strings"
	"testing"
)

// findHeaders runs the rule over src and returns the reported `Name: value`
// pairs.
func findHeaders(src string) []string {
	var out []string
	for _, m := range newHTTPHeaderRule().Find([]byte(src)) {
		out = append(out, m.Value)
	}
	return out
}

func hasHeader(src, want string) bool {
	for _, v := range findHeaders(src) {
		if v == want {
			return true
		}
	}
	return false
}

// TestHTTPHeaderExplicitMaps covers standard and custom names in structurally
// identified header maps. A name alone is intentionally not treated as proof.
func TestHTTPHeaderExplicitMaps(t *testing.T) {
	cases := []struct{ src, want string }{
		{`const headers={Authorization:"Bearer eyJhbGciOiJIUzI1NiJ9"}`, `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9`},
		{`const requestHeaders={"Content-Type":"application/json"}`, `Content-Type: application/json`},
		{`const defaultHeaders={'user-agent': 'JSMiner/1.0'}`, `user-agent: JSMiner/1.0`},
		{"fetch(u,{headers:{Authorization:`Bearer ${token}`}})", "Authorization: Bearer ${token}"},
		{`const extraHeaders={"X-Api-Key":"9f8b7c6d5e4f3a2b1c0d"}`, `X-Api-Key: 9f8b7c6d5e4f3a2b1c0d`},
		{`new Headers({"x-csrf-token":"abc123"})`, `x-csrf-token: abc123`},
		{`fetch(u,{headers:{"X-Tenant-Id":"acme-prod"}})`, `X-Tenant-Id: acme-prod`},
		// The misspelling makes `referer` unmistakable.
		{`const httpHeaders={Referer:"https://internal.example.com/"}`, `Referer: https://internal.example.com/`},
		// A raw header line inside a string literal, CRLF escape trimmed.
		{`var req="Authorization: Bearer sk_live_abc123\r\n";`, `Authorization: Bearer sk_live_abc123`},
	}
	for _, c := range cases {
		if !hasHeader(c.src, c.want) {
			t.Errorf("src %q: want %q, got %v", c.src, c.want, findHeaders(c.src))
		}
	}
}

// TestHTTPHeaderNamesDoNotProveObjectIntent covers false positives observed in
// production bundles. Standard names occur in lookup/config objects, while x-*
// is also a convention for component attributes and CSS selectors.
func TestHTTPHeaderNamesDoNotProveObjectIntent(t *testing.T) {
	drop := []string{
		`const attrs={"x-semi-prop":"children","x-placement":placement}`,
		`createElement("div",{className:c,"x-field-id":id})`,
		`const css=".x-spreadsheet-button:hover{color:red}"`,
		`const metadata={"Content-Type":"panel",Authorization:true}`,
		`const options={sendLDHeaders:{default:true},requestHeaderTransform:{type:"function"}}`,
	}
	for _, src := range drop {
		if got := findHeaders(src); len(got) != 0 {
			t.Errorf("src %q: want no headers, got %v", src, got)
		}
	}
}

func TestHTTPHeaderAnonymousMapNeedsACluster(t *testing.T) {
	src := `merge(target,{"X-LaunchDarkly-Event-Schema":"4","X-LaunchDarkly-Payload-ID":payloadID})`
	for _, want := range []string{
		"X-LaunchDarkly-Event-Schema: 4",
		"X-LaunchDarkly-Payload-ID: payloadID",
	} {
		if !hasHeader(src, want) {
			t.Errorf("want clustered header %q, got %v", want, findHeaders(src))
		}
	}

	// Strong names in separate nested UI objects must not combine into a map.
	nested := `{component:{attrs:{"x-semi-prop":"children"}},popover:{attrs:{"x-placement":"top"}}}`
	if got := findHeaders(nested); len(got) != 0 {
		t.Fatalf("nested attributes formed a false header cluster: %v", got)
	}

	// A security-bearing custom name is independently high-signal and does not
	// need a second, unrelated header to protect its value.
	if !hasHeader(`const h={"X-Api-Key":"9f8b7c6d5e4f"}`, "X-Api-Key: 9f8b7c6d5e4f") {
		t.Fatalf("security-bearing anonymous header was lost: %v", findHeaders(`const h={"X-Api-Key":"9f8b7c6d5e4f"}`))
	}
}

func TestHTTPHeaderRejectsMissingAndControlFlowValues(t *testing.T) {
	src := `{headers:{"Content-Type":void 0,"X-Optional":undefined,"X-Null":null,"X-Literal":"null","X-Enabled":true}}`
	got := findHeaders(src)
	for _, bad := range []string{"Content-Type:", "X-Optional:", "X-Null:"} {
		for _, value := range got {
			if strings.HasPrefix(value, bad) {
				t.Errorf("non-value %q was reported: %v", bad, got)
			}
		}
	}
	for _, want := range []string{"X-Literal: null", "X-Enabled: true"} {
		if !hasHeader(src, want) {
			t.Errorf("want %q, got %v", want, got)
		}
	}

	for _, src := range []string{
		`switch(name){case "content-type":return value}`,
		`const parsers={"Content-Type":function(){}}`,
	} {
		if got := findHeaders(src); len(got) != 0 {
			t.Errorf("control-flow source %q: want no headers, got %v", src, got)
		}
	}
}

// TestHTTPHeaderAmbiguousNamesNeedContext is the heart of the rule: these names
// are registered HTTP headers *and* everyday JS keys, so they are reported only
// inside a header map and never on their own.
func TestHTTPHeaderAmbiguousNamesNeedContext(t *testing.T) {
	// Plain object literals that happen to use header names as keys.
	drop := []string{
		`{name:"Ada",age:30}`,
		`{date:"2024-01-01",author:"x"}`,
		`{host:"localhost",port:8080}`,
		`{origin:"top left",scale:2}`,
		`{location:"Berlin",country:"DE"}`,
		`{server:"primary",region:"eu"}`,
		`{link:"/docs",label:"Docs"}`,
		`{range:[0,10],step:1}`,
		`{expires:3600,renew:!0}`,
		`{allow:"all",deny:"none"}`,
		`{connection:"active",retries:3}`,
		`{from:"alice@example.com",to:"bob@example.com"}`,
		`{vary:"none",warning:"deprecated"}`,
	}
	for _, src := range drop {
		if got := findHeaders(src); len(got) != 0 {
			t.Errorf("src %q: want no headers, got %v", src, got)
		}
	}

	// The same names inside an explicit header map are genuine headers.
	keep := []struct{ src, want string }{
		{`fetch(u,{headers:{Accept:"application/json"}})`, `Accept: application/json`},
		{`fetch(u,{headers:{age:"30"}})`, `age: 30`},
		{`{headers:{Host:"internal.example.com"}}`, `Host: internal.example.com`},
		{`{headers:{Origin:"https://app.example.com"}}`, `Origin: https://app.example.com`},
		// A custom, non-`X-` name is a header purely by virtue of the map.
		{`{headers:{apikey:"abc123def456"}}`, `apikey: abc123def456`},
	}
	for _, c := range keep {
		if !hasHeader(c.src, c.want) {
			t.Errorf("src %q: want %q, got %v", c.src, c.want, findHeaders(c.src))
		}
	}
}

// TestHTTPHeaderBlockScoping checks that context is established structurally, not
// by proximity: a pair after the header map closes must not inherit its anchor.
func TestHTTPHeaderBlockScoping(t *testing.T) {
	// `age` sits within the lookback window of `headers:{` but in a sibling
	// object, so it is not a header.
	src := `fetch(u,{headers:{Accept:"application/json"},body:JSON.stringify({age:30})})`
	for _, v := range findHeaders(src) {
		if strings.HasPrefix(v, "age:") {
			t.Errorf("age escaped its block: got %v", findHeaders(src))
		}
	}
	// The real header in the same expression still reports.
	if !hasHeader(src, `Accept: application/json`) {
		t.Errorf("want Accept header, got %v", findHeaders(src))
	}

	// Nested objects inside the map must not close it prematurely.
	nested := `{headers:{"X-Meta":JSON.stringify({a:{b:1}}),Accept:"text/html"}}`
	if !hasHeader(nested, `Accept: text/html`) {
		t.Errorf("nesting closed the block early: got %v", findHeaders(nested))
	}

	// Braces inside a string value must not disturb the depth count.
	quoted := `{headers:{"X-Tpl":"a}b{c",Accept:"text/plain"}}`
	if !hasHeader(quoted, `Accept: text/plain`) {
		t.Errorf("string braces disturbed depth: got %v", findHeaders(quoted))
	}
}

// TestHTTPHeaderAnchorMustOpenBlock covers constructs, all taken from real
// bundles, where the word `headers` appears but does not open a header block.
// Merely mentioning the stem must not lend header context to a later object.
func TestHTTPHeaderAnchorMustOpenBlock(t *testing.T) {
	drop := []struct{ src, why string }{
		{
			`this.headers=o,this.statusPage=s,this.instance=yy.create({baseURL:e,timeout:t})`,
			"tronweb: an unrelated `headers=o` assignment must not anchor the axios config that follows",
		},
		{
			`Object.defineProperties(Headers.prototype,{enumerable:true,configurable:true})`,
			"node-fetch: `Headers.prototype` must not anchor a property descriptor",
		},
		{
			`Te.headers=e.channel("undici:request:headers")`,
			"prisma/undici: a diagnostics channel name is not a header",
		},
		{
			`const c={url:s,method:s,data:s,baseURL:i,transformRequest:i}`,
			"axios config keys with no header block at all",
		},
		{
			`Object.defineProperties(Request.prototype,{headers:{enumerable:true},method:{enumerable:true}})`,
			"node-fetch: a `headers:{…}` property descriptor holds descriptor keys, not headers",
		},
	}
	for _, c := range drop {
		if got := findHeaders(c.src); len(got) != 0 {
			t.Errorf("%s\n  src %q\n  want no headers, got %v", c.why, c.src, got)
		}
	}

	// A call takes comma-separated arguments, so a `name: value` pair inside its
	// parens is an expression rather than an entry — here socket.io's ternary.
	// The header the call actually sets is still reported, from its first
	// argument; its value is the literal head of the concatenation.
	ternary := `res.setHeader("Content-Type","application/"+(isMap?"json":"javascript")+"; charset=utf-8")`
	for _, v := range findHeaders(ternary) {
		if strings.HasPrefix(v, "json:") {
			t.Errorf("ternary branch reported as a header: got %v", findHeaders(ternary))
		}
	}
	if !hasHeader(ternary, `Content-Type: application/`) {
		t.Errorf("want the header the call sets, got %v", findHeaders(ternary))
	}

	// The genuine block-opening forms must all still anchor.
	keep := []struct{ src, want string }{
		{`fetch(u,{headers:{age:"30"}})`, `age: 30`},
		{`req.headers = {age:"30"}`, `age: 30`},
		{`new Headers({age:"30"})`, `age: 30`},
		{`headers.set("age","30")`, `age: 30`},
		{`headers["age"]="30"`, `age: 30`},
		{`xhr.setRequestHeader("age","30")`, `age: 30`},
	}
	for _, c := range keep {
		if !hasHeader(c.src, c.want) {
			t.Errorf("src %q: want %q, got %v", c.src, c.want, findHeaders(c.src))
		}
	}
}

// TestHTTPHeaderEncodingLabels covers the WHATWG encoding label table, which is
// shaped exactly like a header map and is `x-`-prefixed, so only the names tell
// the two apart.
func TestHTTPHeaderEncodingLabels(t *testing.T) {
	src := `{"x-cp1250":"windows-1250","x-mac-roman":"macintosh","x-sjis":"shift_jis","x-user-defined":"x-user-defined"}`
	if got := findHeaders(src); len(got) != 0 {
		t.Errorf("encoding labels reported as headers: %v", got)
	}
	// A real custom header of the same shape is unaffected.
	if !hasHeader(`{headers:{"x-cp-token":"abc123"}}`, `x-cp-token: abc123`) {
		t.Error("the label exclusions swallowed a real X- header")
	}
}

// TestHTTPHeaderRejectsLookAlikes covers the non-header constructs that share the
// `name: value` shape.
func TestHTTPHeaderRejectsLookAlikes(t *testing.T) {
	drop := []struct{ src, why string }{
		{`{"background-color":"red","font-size":"12px"}`, "CSS properties are kebab-case"},
		{`el.style.cssText="margin-top:10px;border-radius:4px"`, "inline CSS"},
		{`{"data-testid":"submit","data-value":"1"}`, "data-* attributes"},
		{`{"aria-label":"Close","aria-hidden":"true"}`, "aria-* attributes"},
		{`{"x-data":"{open:false}"}`, "Alpine.js directive"},
		{`{"x-show":"visible"}`, "Alpine.js directive"},
		{`{"font-size":"x-small"}`, "CSS keyword value"},
		{`{type:"string",label:"Name"}`, "ordinary object keys"},
		{`cache.set("user","alice")`, "unrelated map .set()"},
		{`{header:{title:"Dashboard",subtitle:"Home"}}`, "singular header: is a UI config"},
	}
	for _, c := range drop {
		if got := findHeaders(c.src); len(got) != 0 {
			t.Errorf("%s: src %q want no headers, got %v", c.why, c.src, got)
		}
	}
}

// TestHTTPHeaderCallForms covers the imperative header-setting APIs.
func TestHTTPHeaderCallForms(t *testing.T) {
	cases := []struct{ src, want string }{
		{`xhr.setRequestHeader("Authorization","Bearer abc123")`, `Authorization: Bearer abc123`},
		// An ambiguous name is admitted here because setRequestHeader anchors it.
		{`xhr.setRequestHeader("Accept","application/json")`, `Accept: application/json`},
		{`h.set("X-Api-Key",k)`, `X-Api-Key: k`},
		{`headers.append("X-Request-Id","req-42")`, `X-Request-Id: req-42`},
		{`myHeaders.append("Age","30")`, `Age: 30`},
		{`new Headers({"X-Internal-Auth":"s3cr3t-value"})`, `X-Internal-Auth: s3cr3t-value`},
		// Node/ethers style.
		{`request.setHeader("content-type","application/json")`, `content-type: application/json`},
		// Assignment into a header map by key.
		{`headers["authorization"]="Basic "+creds`, `authorization: Basic`},
		{`headers["accept-encoding"]="gzip"`, `accept-encoding: gzip`},
		{`req.headers['X-Forwarded-For']=ip`, `X-Forwarded-For: ip`},
		// An ambiguous name is admitted by the `headers` receiver.
		{`headers["age"]="30"`, `age: 30`},
	}
	for _, c := range cases {
		if !hasHeader(c.src, c.want) {
			t.Errorf("src %q: want %q, got %v", c.src, c.want, findHeaders(c.src))
		}
	}

	// `=` is only admitted with a literal `headers` receiver: on shape alone it
	// would sweep in markup attributes and presigned-URL query parameters.
	drop := []string{
		`<div x-data="{open:false}">`,
		`opts["age"]=30`,
		`?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123`,
		`sendLDHeaders["default"]=true`,
		`sendLDHeaders.set("default",true)`,
		// A comparison reads a header rather than setting one, and the `=`
		// separator must not land on the first half of `==`.
		`if(headers["content-type"]==null&&this.bodyType){}`,
	}
	for _, src := range drop {
		if got := findHeaders(src); len(got) != 0 {
			t.Errorf("src %q: want no headers, got %v", src, got)
		}
	}
}

// TestHTTPHeaderSeverity pins the rule's severity to medium.
func TestHTTPHeaderSeverity(t *testing.T) {
	ms := newHTTPHeaderRule().Find([]byte(`{headers:{"X-Api-Key":"9f8b7c6d5e4f"}}`))
	if len(ms) == 0 {
		t.Fatal("no match")
	}
	for _, m := range ms {
		if m.Severity != SeverityLow {
			t.Errorf("severity = %q, want %q", m.Severity, SeverityLow)
		}
		if m.Pattern != httpHeaderPattern {
			t.Errorf("pattern = %q, want %q", m.Pattern, httpHeaderPattern)
		}
	}
}

// TestHTTPHeaderMinifiedBundle exercises the rule on a realistic minified line
// mixing a header map with the object literals that surround it.
func TestHTTPHeaderMinifiedBundle(t *testing.T) {
	src := `function s(e,t){return fetch(e,{method:"POST",headers:{"Content-Type":"application/json","X-Api-Key":"k_live_9f8b7c6d5e4f3a2b",Authorization:"Bearer "+t},body:JSON.stringify({name:e.name,age:e.age,date:Date.now()})}).then(r=>r.json())}`
	got := findHeaders(src)
	want := []string{
		`Content-Type: application/json`,
		`X-Api-Key: k_live_9f8b7c6d5e4f3a2b`,
		// The value is `"Bearer "+t`; the literal is reported, the concatenated
		// variable is not resolvable from source.
		`Authorization: Bearer`,
	}
	for _, w := range want {
		if !hasHeader(src, w) {
			t.Errorf("want %q, got %v", w, got)
		}
	}
	// The body's object keys are not headers even though they follow the map.
	for _, v := range got {
		for _, bad := range []string{"name:", "age:", "date:"} {
			if strings.HasPrefix(v, bad) {
				t.Errorf("body key reported as header: %q (all: %v)", v, got)
			}
		}
	}
}
