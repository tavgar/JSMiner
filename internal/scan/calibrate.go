package scan

import (
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"io"
	"net/url"
	"strconv"
)

// autoCalibrator implements ffuf-style auto-calibration for crawls. Before the
// crawl begins it probes the target with a handful of random, non-existent
// paths to learn what its catch-all / soft-404 responses look like. During the
// crawl it then drops pages that either match one of those wildcard signatures
// or byte-for-byte duplicate a page already scanned, so the crawl spends its
// budget on unique, useful pages instead of endless copies of the same shell.
//
// Wildcard matching uses a coarse (status | word-count | line-count) signature,
// which survives soft-404 pages that echo the requested path back in the body.
// Duplicate detection uses an exact body hash, so two genuinely different pages
// are never collapsed — this keeps real-secret recall intact.
type autoCalibrator struct {
	wildcard   map[string]struct{} // status|words|lines of learned catch-all responses
	seenBodies map[uint64]struct{} // hashes of bodies already accepted
	primed     bool                // the first page (the seed) is always accepted
}

func newAutoCalibrator() *autoCalibrator {
	return &autoCalibrator{
		wildcard:   make(map[string]struct{}),
		seenBodies: make(map[uint64]struct{}),
	}
}

// calibrationProbePaths are the random path shapes used to fingerprint a
// target's catch-all behaviour: a plain segment, a directory, a script-looking
// path and a nested path. Each is filled with a fresh random token per crawl.
func calibrationProbePaths() []string {
	return []string{
		"/" + randToken(20),
		"/" + randToken(20) + "/",
		"/" + randToken(16) + ".js",
		"/" + randToken(10) + "/" + randToken(10),
	}
}

// calibrate probes the seed host with random non-existent paths and records the
// response signatures shared by at least two probes as wildcard signatures.
// Requiring agreement avoids turning a one-off response into a filter that could
// suppress a real page. It returns the number of wildcard signatures learned.
func (c *autoCalibrator) calibrate(seedURL string) int {
	base, err := probeBase(seedURL)
	if err != nil {
		return 0
	}
	counts := make(map[string]int)
	for _, p := range calibrationProbePaths() {
		resp, err := fetchURLResponse(base + p)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		counts[pageSig(resp.StatusCode, data)]++
	}
	for sig, n := range counts {
		if n >= 2 {
			c.wildcard[sig] = struct{}{}
		}
	}
	return len(c.wildcard)
}

// skipPage reports whether a fetched page should be ignored by the crawl. The
// first page it sees (the seed) is always accepted and recorded. Afterwards a
// page is skipped when it matches a learned wildcard signature or duplicates a
// body already accepted.
func (c *autoCalibrator) skipPage(status int, body []byte) bool {
	if !c.primed {
		c.primed = true
		c.seenBodies[hashBody(body)] = struct{}{}
		return false
	}
	if _, ok := c.wildcard[pageSig(status, body)]; ok {
		return true
	}
	h := hashBody(body)
	if _, ok := c.seenBodies[h]; ok {
		return true
	}
	c.seenBodies[h] = struct{}{}
	return false
}

// pageSig builds the coarse wildcard signature for a response: HTTP status,
// word count and line count. Word/line counts are stable when a soft-404 page
// merely echoes the requested (different) path, so two such pages share a
// signature even though their bytes differ.
func pageSig(status int, body []byte) string {
	words := 0
	lines := 1
	inWord := false
	for _, b := range body {
		switch b {
		case '\n':
			lines++
			fallthrough
		case ' ', '\t', '\r', '\f', '\v':
			inWord = false
		default:
			if !inWord {
				inWord = true
				words++
			}
		}
	}
	return strconv.Itoa(status) + "|" + strconv.Itoa(words) + "|" + strconv.Itoa(lines)
}

// hashBody returns a fast non-cryptographic hash of body for exact-duplicate
// detection.
func hashBody(body []byte) uint64 {
	h := fnv.New64a()
	h.Write(body)
	return h.Sum64()
}

// probeBase returns the scheme://host origin of rawURL for building probe URLs.
func probeBase(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// randToken returns a random lowercase-hex token of n hex characters.
func randToken(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a fixed token; calibration degrades gracefully.
		return "calibrationprobe"[:min(n, len("calibrationprobe"))]
	}
	return hex.EncodeToString(b)[:n]
}
