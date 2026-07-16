package scan

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// findByPattern returns the first match with the given pattern, or a zero Match
// and false when none is present.
func findByPattern(ms []Match, pat string) (Match, bool) {
	for _, m := range ms {
		if m.Pattern == pat {
			return m, true
		}
	}
	return Match{}, false
}

// TestSourceMapReference covers detection of the map reference from both the
// //# and legacy //@ comment forms (last-wins), the block-comment form, and the
// SourceMap / X-SourceMap headers (which take precedence).
func TestSourceMapReference(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		header http.Header
		want   string
	}{
		{"hash comment", "code;\n//# sourceMappingURL=app.js.map", nil, "app.js.map"},
		{"legacy at comment", "code;\n//@ sourceMappingURL=old.js.map", nil, "old.js.map"},
		{"block comment", "code;\n/*# sourceMappingURL=b.js.map */", nil, "b.js.map"},
		{"last wins", "//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map", nil, "b.map"},
		{"none", "just some code with no annotation", nil, ""},
		{"header wins", "//# sourceMappingURL=body.map", http.Header{"Sourcemap": {"header.map"}}, "header.map"},
		{"x-sourcemap", "code;", http.Header{"X-Sourcemap": {"x.map"}}, "x.map"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceMapReference([]byte(tc.body), tc.header)
			if got != tc.want {
				t.Fatalf("sourceMapReference = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDecodeDataURI covers base64 and plain (percent-encoded) data: payloads.
func TestDecodeDataURI(t *testing.T) {
	payload := `{"version":3}`
	b64 := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(payload))
	if got, ok := decodeDataURI(b64); !ok || string(got) != payload {
		t.Fatalf("base64 decode = %q ok=%v, want %q", got, ok, payload)
	}
	plain := "data:application/json,%7B%22version%22%3A3%7D"
	if got, ok := decodeDataURI(plain); !ok || string(got) != payload {
		t.Fatalf("plain decode = %q ok=%v, want %q", got, ok, payload)
	}
	withPlus := `{"source":"const sum=a+b"}`
	plainPlus := "data:application/json,%7B%22source%22%3A%22const%20sum%3Da+b%22%7D"
	if got, ok := decodeDataURI(plainPlus); !ok || string(got) != withPlus {
		t.Fatalf("plain plus decode = %q ok=%v, want %q", got, ok, withPlus)
	}
	if _, ok := decodeDataURI("data:application/json"); ok {
		t.Fatal("expected failure on data URI with no comma")
	}
}

// TestScanURLRecoversSourceMap is the core end-to-end check: a minified bundle
// carries no secret but advertises a map whose embedded original source holds a
// JWT and an endpoint. A plain scan (recovery disabled) misses both; with
// recovery the findings surface and are attributed to the original source path.
func TestScanURLRecoversSourceMap(t *testing.T) {
	sourceMapJSON := `{
		"version":3,
		"sources":["webpack:///src/config.js"],
		"sourcesContent":["const token='eyJabc.def.ghi'; fetch('/api/v2/users');"]
	}`
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "console.log(1);\n//# sourceMappingURL=/app.js.map")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Recovery disabled: the minified bundle alone reveals nothing.
	e := NewExtractor(false, false)
	e.SetRecoverSourceMaps(false)
	plain, err := e.ScanURL(ts.URL+"/app.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if hasPattern(plain, "jwt") {
		t.Fatal("did not expect jwt with source-map recovery disabled")
	}

	// Recovery enabled (default): the JWT and endpoint from the original source
	// surface, attributed to the original path.
	e = NewExtractor(false, false)
	matches, err := e.ScanURL(ts.URL+"/app.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := findByPattern(matches, "jwt")
	if !ok {
		t.Fatalf("expected jwt recovered from source map, got %+v", matches)
	}
	if m.Source != "webpack:///src/config.js" {
		t.Fatalf("expected finding attributed to original source, got %q", m.Source)
	}
	if !hasPattern(matches, "endpoint_path") {
		t.Fatalf("expected endpoint recovered from source map, got %+v", matches)
	}
}

// TestScanURLCrawlRecoversSourceMap proves recovered findings flow through the
// crawl reporting path.
func TestScanURLCrawlRecoversSourceMap(t *testing.T) {
	sourceMapJSON := `{"version":3,"sources":["src/secret.js"],"sourcesContent":["const t='eyJabc.def.ghi';"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/app.js"></script></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "var x=1;\n//# sourceMappingURL=app.js.map")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	opts := DefaultCrawlOptions()
	opts.AutoCalibrate = false
	matches, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "jwt") {
		t.Fatalf("expected jwt recovered via crawl, got %+v", matches)
	}
}

// TestSourceMapDataURI recovers a map embedded inline as a base64 data URI.
func TestSourceMapDataURI(t *testing.T) {
	sourceMapJSON := `{"version":3,"sources":["a.js"],"sourcesContent":["var k='eyJabc.def.ghi';"]}`
	dataURI := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(sourceMapJSON))

	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "var x=1;\n//# sourceMappingURL="+dataURI)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	matches, err := e.ScanURL(ts.URL+"/app.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "jwt") {
		t.Fatalf("expected jwt recovered from inline data URI map, got %+v", matches)
	}
}

// TestSourceMapFetchesNonEmbedded fetches an original source over the network
// when the map ships no embedded content but points at an in-scope URL.
func TestSourceMapFetchesNonEmbedded(t *testing.T) {
	sourceMapJSON := `{"version":3,"sourceRoot":"/src/","sources":["orig.js"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "var x=1;\n//# sourceMappingURL=/app.js.map")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	mux.HandleFunc("/src/orig.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "const key='AIzaSyA1234567890123456789012345678901234';")
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	matches, err := e.ScanURL(ts.URL+"/app.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "google_api") {
		t.Fatalf("expected google_api recovered from fetched original, got %+v", matches)
	}
}

// TestSourceMapSkipsVirtualScheme ensures non-fetchable virtual paths without
// embedded content are skipped cleanly rather than fetched or erroring.
func TestSourceMapSkipsVirtualScheme(t *testing.T) {
	sourceMapJSON := `{"version":3,"sources":["webpack://internal/module.js"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "var x=1;\n//# sourceMappingURL=/app.js.map")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	if _, err := e.ScanURL(ts.URL+"/app.js", false, false, false); err != nil {
		t.Fatalf("unexpected error with unfetchable virtual source: %v", err)
	}
}

// TestSourceMapHeader recovers a map advertised via the SourceMap response
// header rather than an in-body comment.
func TestSourceMapHeader(t *testing.T) {
	sourceMapJSON := `{"version":3,"sources":["h.js"],"sourcesContent":["var k='eyJabc.def.ghi';"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("SourceMap", "/app.js.map")
		io.WriteString(w, "var x=1;")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	matches, err := e.ScanURL(ts.URL+"/app.js", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "jwt") {
		t.Fatalf("expected jwt recovered via SourceMap header, got %+v", matches)
	}
}

// TestScanURLPostsRecoversSourceMap recovers POST endpoints from original source.
func TestScanURLPostsRecoversSourceMap(t *testing.T) {
	sourceMapJSON := `{"version":3,"sources":["p.js"],"sourcesContent":["fetch('/api/login',{method:'POST',body:JSON.stringify({user:'a'})});"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "var x=1;\n//# sourceMappingURL=/app.js.map")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, sourceMapJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(false, false)
	matches, err := e.ScanURLPosts(ts.URL+"/app.js", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPattern(matches, "post_path") && !hasPattern(matches, "post_url") {
		t.Fatalf("expected POST endpoint recovered from source map, got %+v", matches)
	}
}
