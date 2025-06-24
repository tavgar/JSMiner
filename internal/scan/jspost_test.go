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
	e := NewExtractor(true)
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
	e := NewExtractor(true)
	matches, err := e.ScanReaderPostRequests("file.txt", strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}
