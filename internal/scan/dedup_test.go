package scan

import "testing"

// TestDedupMatchesByValueKeepSeverity proves that when one value is reported by
// several signals at different severities, only the highest-severity finding
// survives, while a value reported only once (an endpoint here) is untouched.
func TestDedupMatchesByValueKeepSeverity(t *testing.T) {
	in := []Match{
		{Pattern: "aws_access_key", Value: "AKIAIOSFODNN7EXAMPLE", Severity: SeverityHigh},
		{Pattern: "generic_api_key", Value: "AKIAIOSFODNN7EXAMPLE", Severity: SeverityMedium},
		{Pattern: "high_entropy_string", Value: "AKIAIOSFODNN7EXAMPLE", Severity: SeverityInfo},
		{Pattern: "endpoint_url", Value: "https://api.example.com/v1", Severity: SeverityInfo},
	}
	out := DedupMatchesByValueKeepSeverity(in)
	if len(out) != 2 {
		t.Fatalf("want 2 findings (the high AKIA + the unique endpoint), got %d: %+v", len(out), out)
	}
	for _, m := range out {
		if m.Value == "AKIAIOSFODNN7EXAMPLE" && m.Severity != SeverityHigh {
			t.Errorf("kept the wrong severity for the deduped value: %s", m.Severity)
		}
	}
}

// TestDedupMatchesByValueKeepsTopBandAndEmpties proves ties at the top severity
// are all kept (a distinct high signal is never dropped) and that empty-valued
// findings — which are not comparable — are left alone.
func TestDedupMatchesByValueKeepsTopBandAndEmpties(t *testing.T) {
	in := []Match{
		{Pattern: "a", Value: "x", Severity: SeverityHigh},
		{Pattern: "b", Value: "x", Severity: SeverityHigh}, // tie at top -> both kept
		{Pattern: "c", Value: "x", Severity: SeverityLow},  // dominated -> dropped
		{Pattern: "d", Value: "", Severity: SeverityLow},   // empty value -> untouched
		{Pattern: "e", Value: "", Severity: SeverityInfo},  // empty value -> untouched
	}
	out := DedupMatchesByValueKeepSeverity(in)
	if len(out) != 4 {
		t.Fatalf("want 4 (two top-band 'x' + two empties), got %d: %+v", len(out), out)
	}
	for _, m := range out {
		if m.Value == "x" && m.Severity == SeverityLow {
			t.Error("low-severity duplicate of a high value should have been dropped")
		}
	}
}

// TestDedupMatchesByValuePreservesOrder keeps the surviving findings in their
// original relative order, so output stays stable.
func TestDedupMatchesByValuePreservesOrder(t *testing.T) {
	in := []Match{
		{Pattern: "p1", Value: "a", Severity: SeverityLow},
		{Pattern: "p2", Value: "b", Severity: SeverityHigh},
		{Pattern: "p3", Value: "a", Severity: SeverityHigh}, // dominates the first 'a'
	}
	out := DedupMatchesByValueKeepSeverity(in)
	if len(out) != 2 || out[0].Value != "b" || out[1].Pattern != "p3" {
		t.Fatalf("unexpected order/content: %+v", out)
	}
}
