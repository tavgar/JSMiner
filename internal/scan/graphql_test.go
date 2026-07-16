package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsGraphQLEndpoint(t *testing.T) {
	yes := []string{
		"https://x.com/graphql",
		"https://x.com/api/graphql",
		"https://x.com/graphql/",
		"https://x.com/v1/graphql?foo=1",
		"https://x.com/graphiql",
	}
	no := []string{
		"https://x.com/graphqlish", // substring, not a whole segment
		"https://x.com/api/users",
		"https://x.com/graph",
	}
	for _, u := range yes {
		if !isGraphQLEndpoint(u) {
			t.Errorf("isGraphQLEndpoint(%s) = false, want true", u)
		}
	}
	for _, u := range no {
		if isGraphQLEndpoint(u) {
			t.Errorf("isGraphQLEndpoint(%s) = true, want false", u)
		}
	}
}

// graphqlServer serves an introspection response when enabled, or an
// introspection-disabled error otherwise.
func graphqlServer(enabled bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !enabled {
			io.WriteString(w, `{"errors":[{"message":"GraphQL introspection is not allowed"}]}`)
			return
		}
		io.WriteString(w, `{"data":{"__schema":{
			"queryType":{"name":"Query"},
			"mutationType":{"name":"Mutation"},
			"subscriptionType":null,
			"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},{"name":"__Type","kind":"OBJECT"}]
		}}}`)
	}))
}

func TestProbeGraphQLIntrospectionEnabled(t *testing.T) {
	ts := graphqlServer(true)
	defer ts.Close()

	m, ok := probeGraphQLIntrospection(ts.URL + "/graphql")
	if !ok {
		t.Fatal("expected a finding when introspection is enabled")
	}
	if m.Pattern != GraphQLIntrospectionPattern {
		t.Errorf("pattern = %q, want %q", m.Pattern, GraphQLIntrospectionPattern)
	}
	if !strings.Contains(m.Params, "introspection=enabled") ||
		!strings.Contains(m.Params, "query=Query") ||
		!strings.Contains(m.Params, "mutation=Mutation") {
		t.Errorf("params missing schema summary: %q", m.Params)
	}
	// Only the two user-defined types count; __Type is excluded.
	if !strings.Contains(m.Params, "types=2") {
		t.Errorf("params should report 2 user types, got %q", m.Params)
	}
}

func TestProbeGraphQLIntrospectionDisabled(t *testing.T) {
	ts := graphqlServer(false)
	defer ts.Close()
	if _, ok := probeGraphQLIntrospection(ts.URL + "/graphql"); ok {
		t.Fatal("expected no finding when introspection is disabled")
	}
}

// TestScanURLCrawlProbesGraphQL verifies the crawl reaches a /graphql endpoint
// discovered on the seed and reports its introspection finding.
func TestScanURLCrawlProbesGraphQL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script>fetch('/api/graphql');</script></html>`)
	})
	mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			// A bare GET returns an error, as many GraphQL servers do.
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"must POST a query"}]}`)
			return
		}
		io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT"}]}}}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	e := NewExtractor(true, false)
	// ProbeMethods on so active probing (including introspection) runs.
	opts := CrawlOptions{MaxDepth: 2, MaxPages: 10, SameScopeOnly: true, ProbeMethods: true, RequestMethods: defaultRequestMethods()}
	ms, err := e.ScanURLCrawl(ts.URL, false, false, false, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Pattern == GraphQLIntrospectionPattern && strings.HasSuffix(m.Value, "/api/graphql") {
			return
		}
	}
	t.Fatal("GraphQL introspection finding not reported for the crawled endpoint")
}
