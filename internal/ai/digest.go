package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Digest caps. A digest is meant to be a cheap, bounded summary of a site's URL
// vocabulary — not a full crawl dump — so the synthesis request stays small and
// its cost predictable regardless of how large the target is.
const (
	maxDigestTemplates = 150
	maxDigestLevels    = 60
	maxDigestSamples   = 20
)

// SiteDigest is a compact, structural summary of a target that is cheap to build
// from state the crawl already computes (template classes, discovered directory
// levels, a few sample URLs). It is the sole input to policy synthesis: the model
// sees the shape of the site — which route templates exist and how often each
// recurs — rather than a stream of individual URLs, which is what keeps the
// synthesis to one bounded request instead of scaling with the crawl.
type SiteDigest struct {
	// Origin is the scheme://host the digest describes.
	Origin string `json:"origin"`

	// Templates are normalised URL template keys (e.g. host/product/{}), each the
	// canonical shape of a class of pages that differ only in data. Counts maps a
	// template to how many instances of it have been seen, so the model can tell a
	// high-volume low-yield class (thousands of profile pages) from a singleton
	// route that is likely an app or API root.
	Templates []string       `json:"templates"`
	Counts    map[string]int `json:"counts,omitempty"`

	// Levels are the distinct directory levels discovered (e.g. /, /api/, /admin/),
	// the vocabulary of path prefixes the site exposes.
	Levels []string `json:"levels,omitempty"`

	// Samples are a handful of real discovered URLs, giving the model concrete
	// examples of extensions and query shapes behind the templates.
	Samples []string `json:"samples,omitempty"`
}

// Compact bounds and canonicalises the digest so the synthesis request is small
// and, crucially, deterministic: identical crawl state always produces the same
// digest bytes, which is what makes the on-disk cache key stable across runs. It
// sorts every slice, dedupes, and truncates each to its cap.
func (d SiteDigest) Compact() SiteDigest {
	out := SiteDigest{Origin: d.Origin}
	out.Templates = capStrings(uniqueSorted(d.Templates), maxDigestTemplates)
	out.Levels = capStrings(uniqueSorted(d.Levels), maxDigestLevels)
	out.Samples = capStrings(uniqueSorted(d.Samples), maxDigestSamples)
	if len(d.Counts) > 0 {
		out.Counts = make(map[string]int, len(out.Templates))
		for _, t := range out.Templates {
			if c, ok := d.Counts[t]; ok {
				out.Counts[t] = c
			}
		}
	}
	return out
}

// Empty reports whether the digest carries no structural signal worth a synthesis
// call (no templates, levels or samples). Callers skip the API entirely in that
// case, so a near-empty seed never pays for a request that can't help.
func (d SiteDigest) Empty() bool {
	return len(d.Templates) == 0 && len(d.Levels) == 0 && len(d.Samples) == 0
}

// Fingerprint is a stable content hash of the compacted digest plus the model
// identity, used as the on-disk cache key. Two crawls of the same site that
// discover the same structure and target the same model reuse one cached policy;
// a change in structure or model produces a new key and a fresh synthesis.
func (d SiteDigest) Fingerprint(model string) string {
	c := d.Compact()
	h := sha256.New()
	h.Write([]byte(model))
	h.Write([]byte{0})
	h.Write([]byte(c.Origin))
	h.Write([]byte{0})
	for _, t := range c.Templates {
		h.Write([]byte(t))
		h.Write([]byte{'#'})
		h.Write([]byte(strconv.Itoa(c.Counts[t])))
		h.Write([]byte{0})
	}
	h.Write([]byte{'\n'})
	for _, l := range c.Levels {
		h.Write([]byte(l))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func capStrings(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}
