package jsast

import (
	"testing"
)

// basic sanity test for ExtractValues using simple JS string
func TestExtractValues(t *testing.T) {
	js := []byte(`const a = "foo";`)
	vals := ExtractValues(js)
	if len(vals) == 0 {
		t.Fatal("expected values")
	}
}
