package scan

import (
	"reflect"
	"testing"
)

func TestDOMSeedURLsFromMatches(t *testing.T) {
	matches := []Match{
		{Source: "https://app.test/assets/app.js", Pattern: "endpoint_path", Value: "/account/view?tab=profile"},
		{Source: "https://app.test/", Pattern: "endpoint_path", Value: "/assets/chunk.js"},
		{Source: "https://app.test/", Pattern: "endpoint_url", Value: "https://outside.test/page"},
		{Source: "https://app.test/", Pattern: GatheredURLPattern, Value: "https://app.test/archive"},
	}
	got := DOMSeedURLsFromMatches("https://app.test/", matches, false, 10)
	want := []string{"https://app.test/account/view?tab=profile", "https://app.test/archive"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DOM seeds = %v, want %v", got, want)
	}
}
