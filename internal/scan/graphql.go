package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// GraphQLIntrospectionPattern is the Match.Pattern for a confirmed GraphQL
// endpoint whose introspection is enabled. Introspection exposes the whole schema
// — every query, mutation and type — to any client, so besides mapping the API's
// surface it is a finding in its own right: production endpoints are expected to
// disable it.
const GraphQLIntrospectionPattern = "graphql_introspection"

// graphqlIntrospectionQuery is a minimal introspection query: enough to confirm
// introspection is on and to summarise the schema (root operation type names and
// the type list) without pulling every field and argument, which on a large schema
// would be a large response.
const graphqlIntrospectionQuery = `{"query":"query{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind}}}"}`

// isGraphQLEndpoint reports whether rawURL looks like a GraphQL endpoint, based on
// a path segment of "graphql", "graphiql" or "graphql-api". Keying on a whole
// segment (not a substring) keeps unrelated paths from being probed.
func isGraphQLEndpoint(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(u.Path), "/") {
		switch seg {
		case "graphql", "graphiql", "graphql-api":
			return true
		}
	}
	return false
}

// graphqlSchemaResponse models just the parts of an introspection response this
// probe reads.
type graphqlSchemaResponse struct {
	Data struct {
		Schema struct {
			QueryType        *struct{ Name string } `json:"queryType"`
			MutationType     *struct{ Name string } `json:"mutationType"`
			SubscriptionType *struct{ Name string } `json:"subscriptionType"`
			Types            []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// probeGraphQLIntrospection sends the introspection query to endpointURL and, when
// the server answers with a real schema, returns a finding recording that
// introspection is enabled and summarising the schema (root operation type names
// and the count of user-defined types). ok is false when the endpoint does not
// answer, is not GraphQL, or has introspection disabled — so the crawl reports the
// finding only when it is real. It issues a single POST and reads a bounded body.
func probeGraphQLIntrospection(endpointURL string) (Match, bool) {
	resp, err := fetchURLResponseMethodSameScope(endpointURL, "POST", graphqlIntrospectionQuery)
	if err != nil {
		return Match{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Match{}, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Match{}, false
	}
	var out graphqlSchemaResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return Match{}, false
	}
	sch := out.Data.Schema
	// A genuine introspection result names a query root and/or carries the type
	// list. Without either, this is an error body or a non-GraphQL endpoint.
	if sch.QueryType == nil && sch.MutationType == nil && len(sch.Types) == 0 {
		return Match{}, false
	}

	userTypes := 0
	for _, tp := range sch.Types {
		if !strings.HasPrefix(tp.Name, "__") { // skip introspection's own meta-types
			userTypes++
		}
	}
	parts := []string{"introspection=enabled", fmt.Sprintf("types=%d", userTypes)}
	if sch.QueryType != nil && sch.QueryType.Name != "" {
		parts = append(parts, "query="+sch.QueryType.Name)
	}
	if sch.MutationType != nil && sch.MutationType.Name != "" {
		parts = append(parts, "mutation="+sch.MutationType.Name)
	}
	if sch.SubscriptionType != nil && sch.SubscriptionType.Name != "" {
		parts = append(parts, "subscription="+sch.SubscriptionType.Name)
	}
	return Match{
		Source:   endpointURL,
		Pattern:  GraphQLIntrospectionPattern,
		Value:    endpointURL,
		Params:   strings.Join(parts, " "),
		Severity: "info",
	}, true
}
