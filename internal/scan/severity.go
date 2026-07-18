package scan

import (
	"sort"
	"strings"
)

// Severity levels rank a finding by how likely it is to be a real, directly
// exploitable secret, so the output can lead with what matters.
//
//   - High: distinctive credential formats (provider tokens, cloud keys, JWTs)
//     whose signature alone makes a match almost certainly a live secret.
//   - Medium: keyword-anchored credentials (`api_key=...`, `password: ...`) that
//     are probably secrets but carry more false positives and warrant review.
//   - Low: findings that only occasionally reveal something sensitive — HTTP
//     headers, for instance, are usually mundane and worth a look, not an alarm.
//   - Info: non-secret intelligence — endpoints, URLs, emails, paths, IPs and
//     generic high-entropy strings — that is useful context, not a leak.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// severityRank maps a severity label to a sort weight; higher sorts first.
// Unknown labels rank below info so a mislabelled rule never displaces a real
// finding.
func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// SortBySeverity orders matches from highest to lowest severity, preserving the
// original relative order within each band so discovery order is kept for ties.
func SortBySeverity(ms []Match) {
	sort.SliceStable(ms, func(i, j int) bool {
		return severityRank(ms[i].Severity) > severityRank(ms[j].Severity)
	})
}
