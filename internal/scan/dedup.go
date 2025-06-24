package scan

// UniqueMatches returns a new slice containing only the first occurrence of each
// pattern/value pair from ms. The original order is preserved for the first
// occurrence.
func UniqueMatches(ms []Match) []Match {
	seen := make(map[string]struct{})
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		key := m.Pattern + "|" + m.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}
