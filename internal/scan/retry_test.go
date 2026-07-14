package scan

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// hijackClose aborts the current request's connection without responding, forcing
// the client to observe a transport error (the transient failure retries guard
// against).
func hijackClose(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}
}

// TestFetchRetriesTransientError verifies a bodyless fetch that hits a transient
// transport error is retried and ultimately succeeds, so one network hiccup does
// not silently drop a page from the crawl.
func TestFetchRetriesTransientError(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()
	SetSkipTLSVerification(true)
	orig := FetchRetries
	SetFetchRetries(2)
	defer SetFetchRetries(orig)
	ResetThrottle()

	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&n, 1) == 1 {
			hijackClose(w) // fail the first attempt
			return
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	resp, err := fetchURLResponse(ts.URL)
	if err != nil {
		t.Fatalf("expected retry to recover, got error: %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt64(&n); got < 2 {
		t.Fatalf("expected at least 2 attempts (failure + retry), got %d", got)
	}
}

// TestFetchNoRetryForBodyRequests verifies a body-bearing request (a discovered
// POST/PUT/PATCH parameter replay) is attempted exactly once even when retries are
// configured, so a retry can never double-submit it against the target.
func TestFetchNoRetryForBodyRequests(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()
	SetSkipTLSVerification(true)
	orig := FetchRetries
	SetFetchRetries(3)
	defer SetFetchRetries(orig)
	ResetThrottle()

	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		hijackClose(w)
	}))
	defer ts.Close()

	if _, err := fetchURLResponseMethod(ts.URL, "POST", "x=1"); err == nil {
		t.Fatal("expected error from an always-failing POST")
	}
	if got := atomic.LoadInt64(&n); got != 1 {
		t.Fatalf("POST attempted %d times; body-bearing requests must run once (double-submit risk)", got)
	}
}

// TestFetchRetriesDisabled verifies SetFetchRetries(0) restores single-attempt
// behaviour on the bodyless path.
func TestFetchRetriesDisabled(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()
	SetSkipTLSVerification(true)
	orig := FetchRetries
	SetFetchRetries(0)
	defer SetFetchRetries(orig)
	ResetThrottle()

	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		hijackClose(w)
	}))
	defer ts.Close()

	if _, err := fetchURLResponse(ts.URL); err == nil {
		t.Fatal("expected error with retries disabled")
	}
	if got := atomic.LoadInt64(&n); got != 1 {
		t.Fatalf("expected exactly 1 attempt with retries disabled, got %d", got)
	}
}
