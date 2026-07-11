package scan

import (
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"
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
//
// Calibration is also performed per directory level, lazily. Many sites answer
// unknown paths differently depending on the level: a marketing 404 shell at the
// root, a generic JSON error under /api/, a section soft-404 under /docs/. The
// root probe alone cannot see those, so the first time the crawl reaches a new
// level it probes that level with random paths and learns its own catch-all
// fingerprint, then skips pages under that level that match it.
type autoCalibrator struct {
	wildcard   map[string]struct{}            // status|words|lines of the root catch-all responses (GET)
	levelWild  map[string]map[string]struct{} // per-directory-level catch-all signatures (GET)
	levelDone  map[string]struct{}            // levels already probed (even if they learned nothing)
	seenBodies map[uint64]struct{}            // hashes of bodies already accepted
	base       string                         // scheme://host origin used to build level probes
	primed     bool                           // the first page (the seed) is always accepted

	// methodWild holds the catch-all/error fingerprint learned per request method
	// and directory level, so the crawler knows what a "this verb is not handled
	// here" response looks like independently for GET, POST, PUT, and so on. The
	// key is method+"\x00"+level. methodDone tracks which (method, level) pairs
	// have already been probed so each is fingerprinted at most once per crawl.
	methodWild map[string]map[string]struct{}
	methodDone map[string]struct{}
}

func newAutoCalibrator() *autoCalibrator {
	return &autoCalibrator{
		wildcard:   make(map[string]struct{}),
		levelWild:  make(map[string]map[string]struct{}),
		levelDone:  make(map[string]struct{}),
		seenBodies: make(map[uint64]struct{}),
		methodWild: make(map[string]map[string]struct{}),
		methodDone: make(map[string]struct{}),
	}
}

// setBase records the scheme://host origin used to build probe URLs. It lets the
// per-method calibration run even when whole-page auto-calibration (calibrate)
// was not performed, so method probing is self-sufficient.
func (c *autoCalibrator) setBase(seedURL string) {
	if base, err := probeBase(seedURL); err == nil {
		c.base = base
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
	// Remember the origin so per-level probes can be built during the crawl, and
	// mark the root level as already probed: its catch-all lives in c.wildcard.
	c.base = base
	c.levelDone["/"] = struct{}{}
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
// page is skipped when it matches the root catch-all signature, matches the
// catch-all signature of its own directory level, or duplicates a body already
// accepted. pageURL identifies the level to check (and to lazily calibrate on
// first sight).
func (c *autoCalibrator) skipPage(pageURL string, status int, body []byte) bool {
	if !c.primed {
		c.primed = true
		c.seenBodies[hashBody(body)] = struct{}{}
		return false
	}
	sig := pageSig(status, body)
	if _, ok := c.wildcard[sig]; ok {
		return true
	}
	lvl := levelOf(pageURL)
	c.ensureLevel(lvl)
	if sigs, ok := c.levelWild[lvl]; ok {
		if _, hit := sigs[sig]; hit {
			return true
		}
	}
	h := hashBody(body)
	if _, ok := c.seenBodies[h]; ok {
		return true
	}
	c.seenBodies[h] = struct{}{}
	return false
}

// ensureLevel probes lvl the first time it is seen and records the signatures
// shared by at least two probes as that level's catch-all fingerprint. A level
// is marked done even when it learns nothing, so it is probed at most once per
// crawl. Levels are probed lazily — only for levels the crawl actually reaches —
// so the extra requests scale with the number of distinct directories visited,
// not with the whole URL space.
func (c *autoCalibrator) ensureLevel(lvl string) {
	if c.base == "" {
		return
	}
	if _, ok := c.levelDone[lvl]; ok {
		return
	}
	c.levelDone[lvl] = struct{}{}

	counts := make(map[string]int)
	for _, p := range levelProbePaths(lvl) {
		resp, err := fetchURLResponse(c.base + p)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		counts[pageSig(resp.StatusCode, data)]++
	}
	var sigs map[string]struct{}
	for sig, n := range counts {
		if n >= 2 {
			if sigs == nil {
				sigs = make(map[string]struct{})
			}
			sigs[sig] = struct{}{}
		}
	}
	if sigs != nil {
		c.levelWild[lvl] = sigs
	}
}

// methodKey builds the map key for a (method, level) fingerprint.
func methodKey(method, level string) string { return method + "\x00" + level }

// ensureMethodLevel probes the given directory level with the given HTTP method
// the first time that (method, level) pair is seen, recording the response
// signatures shared by at least two random probes as the catch-all/error
// fingerprint for that verb at that level. This is the per-request-type error
// logic: a level that answers unknown POSTs with a 405 shell and unknown GETs
// with a 404 shell learns a distinct fingerprint for each. Probing is lazy and
// bounded (three probes per pair) so the extra requests scale with the number of
// (method, level) pairs the crawl actually reaches.
func (c *autoCalibrator) ensureMethodLevel(method, lvl string) {
	if c.base == "" {
		return
	}
	key := methodKey(method, lvl)
	if _, ok := c.methodDone[key]; ok {
		return
	}
	c.methodDone[key] = struct{}{}

	counts := make(map[string]int)
	for _, p := range levelProbePaths(lvl) {
		resp, err := fetchURLResponseMethod(c.base+p, method, "")
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		counts[pageSig(resp.StatusCode, data)]++
	}
	var sigs map[string]struct{}
	for sig, n := range counts {
		if n >= 2 {
			if sigs == nil {
				sigs = make(map[string]struct{})
			}
			sigs[sig] = struct{}{}
		}
	}
	if sigs != nil {
		c.methodWild[key] = sigs
	}
}

// methodCatchAll reports whether a response to method at pageURL's directory
// level matches that level's learned catch-all/error fingerprint for that verb.
// It lazily calibrates the (method, level) pair on first sight. A true result
// means "this verb is not really handled here" — the response is the level's
// standard rejection shell — so the caller should not treat the method as
// working.
func (c *autoCalibrator) methodCatchAll(method, pageURL string, status int, body []byte) bool {
	lvl := levelOf(pageURL)
	c.ensureMethodLevel(method, lvl)
	if sigs, ok := c.methodWild[methodKey(method, lvl)]; ok {
		if _, hit := sigs[pageSig(status, body)]; hit {
			return true
		}
	}
	return false
}

// levelProbePaths are the random path shapes used to fingerprint a directory
// level's catch-all behaviour: a plain child, a child directory and a
// script-looking child. lvl already ends with a slash.
func levelProbePaths(lvl string) []string {
	return []string{
		lvl + randToken(20),
		lvl + randToken(20) + "/",
		lvl + randToken(16) + ".js",
	}
}

// levelOf returns the directory level of rawURL — the parent path that a
// catch-all would be probed under. It always ends with a slash, so "/api/v1/x"
// and "/api/v1/" both map to "/api/v1/" and a URL at the root maps to "/".
func levelOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	dir := path.Dir(u.Path)
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir
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
