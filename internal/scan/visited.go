package scan

import "sync"

// visitedSet is the concurrency-safe set of URLs already fetched during a scan or
// crawl. A single set is shared across every page a crawl scans so a JS bundle
// referenced from many pages — or a source map shared by several bundles — is
// fetched and scanned only once. A concurrent crawl scans several pages at the
// same time, so that shared bookkeeping has to be synchronised; the mutex here is
// what makes the sharing safe. The zero value is not usable; call newVisitedSet.
type visitedSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

// newVisitedSet returns an empty, ready-to-use visited set.
func newVisitedSet() *visitedSet {
	return &visitedSet{m: make(map[string]struct{})}
}

// visit records u as visited and reports whether it was newly added. A false
// result means u had already been visited, so the caller should not fetch it
// again. It is safe to call from multiple goroutines: the check and the insert
// happen atomically, so two workers racing on the same URL can never both be told
// to proceed. A nil receiver admits everything (reporting true) so callers that
// scan a single URL without a shared set can pass nil.
func (v *visitedSet) visit(u string) bool {
	if v == nil {
		return true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[u]; ok {
		return false
	}
	v.m[u] = struct{}{}
	return true
}

// snapshot returns the visited URLs as a slice. It is used to persist a crawl
// checkpoint and is safe to call while workers are visiting concurrently.
func (v *visitedSet) snapshot() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.m))
	for u := range v.m {
		out = append(out, u)
	}
	return out
}

// addAll marks every URL in us as visited, used to preload a resumed crawl so
// already-fetched pages are not fetched again.
func (v *visitedSet) addAll(us []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, u := range us {
		v.m[u] = struct{}{}
	}
}
