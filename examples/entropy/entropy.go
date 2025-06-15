package main

import (
	"math"
	"regexp"

	"github.com/tavgar/JSMiner/internal/scan"
)

// EntropyRule flags strings with high Shannon entropy.
type EntropyRule struct{}

func (EntropyRule) MatchName() string { return "entropy" }

func entropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	for _, c := range freq {
		p := c / float64(len(s))
		ent -= p * math.Log2(p)
	}
	return ent
}

var candidate = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)

func (EntropyRule) Find(data []byte) []scan.Match {
	var out []scan.Match
	for _, b := range candidate.FindAll(data, -1) {
		s := string(b)
		if entropy(s) >= 4.5 {
			out = append(out, scan.Match{Pattern: "entropy", Value: s, Severity: "high"})
		}
	}
	return out
}

func init() {
	scan.RegisterRule(EntropyRule{})
}
