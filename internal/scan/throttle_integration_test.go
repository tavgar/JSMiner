package scan

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchAppliesThrottleBackoff exercises the real fetch path: a server that
// answers the first request with 429+Retry-After must cause the throttle to
// delay the following request. It runs against the process-wide globalThrottle,
// so it swaps in a virtual clock and restores the throttle afterwards.
func TestFetchAppliesThrottleBackoff(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	var totalSlept time.Duration

	saved := globalThrottle
	globalThrottle = newRequestThrottle()
	globalThrottle.now = func() time.Time { return cur }
	globalThrottle.sleep = func(d time.Duration) {
		totalSlept += d
		cur = cur.Add(d)
	}
	defer func() { globalThrottle = saved }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// First request: server returns 429, throttle records the backoff.
	if _, err := fetchURLResponseMethod(srv.URL, "GET", ""); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	// Second request: the throttle should have slept for ~Retry-After before it.
	if _, err := fetchURLResponseMethod(srv.URL, "GET", ""); err != nil {
		t.Fatalf("second fetch: %v", err)
	}

	if totalSlept < 7*time.Second {
		t.Fatalf("expected the fetch path to honour Retry-After 7s, slept only %s", totalSlept)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("expected 2 server hits, got %d", hits)
	}
}
