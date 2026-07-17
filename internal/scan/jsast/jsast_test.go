package jsast

import (
	"fmt"
	"reflect"
	"strings"
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

func TestExtractReconstructedValues(t *testing.T) {
	js := []byte(`
		const ordinary = "already contiguous";
		const joined = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789";
		const escaped = "line\u002Dbreak";
		const duplicate = "joined" + "value";
		const elsewhere = "joinedvalue";
	`)
	got := ExtractReconstructedValues(js)
	want := []string{
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"line-break",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractReconstructedValues() = %q, want %q", got, want)
	}

	all := ExtractValues(js)
	var filtered []string
	for _, value := range all {
		if !strings.Contains(string(js), value) {
			filtered = append(filtered, value)
		}
	}
	if !reflect.DeepEqual(got, filtered) {
		t.Fatalf("optimized reconstructed values = %q, legacy filter = %q", got, filtered)
	}
}

func BenchmarkExtractReconstructedValues(b *testing.B) {
	var src strings.Builder
	for i := 0; i < 10_000; i++ {
		fmt.Fprintf(&src, `const value%d = "ordinary-value-%d";`, i, i)
	}
	src.WriteString(`const token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789";`)
	data := []byte(src.String())

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractReconstructedValues(data)
	}
}
