package scan

// UniqueMatches returns a new slice containing only the first occurrence of each
// pattern/value pair from ms. The original order is preserved for the first
// occurrence.
func UniqueMatches(ms []Match) []Match {
	seen := make(map[string]struct{})
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		key := m.Pattern + "|" + m.Value + "|" + m.Params
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

// DedupMatchesByValueKeepSeverity removes lower-severity duplicates of a value.
// When the same value is reported by more than one signal, only the finding(s)
// at the highest severity seen for that value are kept, so a real credential
// flagged by a specific high-signal rule is never buried under the generic
// low-signal echoes of the same string (a high signal always wins over a low one
// for the identical value). Findings whose value is unique — and empty-valued
// findings, which are not comparable — are untouched, and the input order is
// otherwise preserved. Run this last, after all sources have been merged.
func DedupMatchesByValueKeepSeverity(ms []Match) []Match {
	maxRank := make(map[string]int, len(ms))
	for _, m := range ms {
		if m.Value == "" {
			continue
		}
		if r := severityRank(m.Severity); r > maxRank[m.Value] {
			maxRank[m.Value] = r
		}
	}
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		if m.Value != "" && severityRank(m.Severity) < maxRank[m.Value] {
			continue
		}
		out = append(out, m)
	}
	return out
}
