package scan

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// resetSharedClient clears the cached fetch client so a test starts from a known
// state regardless of what ran before it.
func resetSharedClient() {
	httpClientMu.Lock()
	sharedClient = nil
	sharedClientBuilt = false
	httpClientMu.Unlock()
}

// TestSharedHTTPClientReused verifies the fetch path reuses one client (and thus
// its keep-alive connection pool) across requests, rather than building a fresh
// client — and transport — every time.
func TestSharedHTTPClientReused(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()

	a := sharedHTTPClient()
	b := sharedHTTPClient()
	if a != b {
		t.Fatal("sharedHTTPClient built a new client when config was unchanged")
	}
}

// TestSharedHTTPClientRebuiltOnConfigChange verifies the cached client is rebuilt
// when a baked-in setting (TLS verification, timeout) changes, so configuration
// updates are never silently ignored.
func TestSharedHTTPClientRebuiltOnConfigChange(t *testing.T) {
	resetSharedClient()
	origTLS := SkipTLSVerification
	origTimeout := HTTPClientTimeout
	defer func() {
		SkipTLSVerification = origTLS
		HTTPClientTimeout = origTimeout
		resetSharedClient()
	}()

	SetSkipTLSVerification(true)
	first := sharedHTTPClient()

	SetSkipTLSVerification(false)
	if second := sharedHTTPClient(); second == first {
		t.Fatal("client not rebuilt after SkipTLSVerification changed")
	}

	third := sharedHTTPClient()
	SetHTTPTimeout(33)
	if fourth := sharedHTTPClient(); fourth == third {
		t.Fatal("client not rebuilt after HTTPClientTimeout changed")
	}
}

// TestSharedHTTPClientKeepAlive drives several requests through the shared client
// against one server and asserts the server observed connection reuse — the
// concrete payoff of not rebuilding the transport per request.
func TestSharedHTTPClientKeepAlive(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()
	SetSkipTLSVerification(true)

	var conns int64
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt64(&conns, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	for i := 0; i < 5; i++ {
		resp, err := fetchURLResponse(ts.URL)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		// Drain and close so the connection returns to the idle pool for reuse.
		readCappedBody(resp.Body)
		resp.Body.Close()
	}

	if got := atomic.LoadInt64(&conns); got != 1 {
		t.Fatalf("opened %d connections for 5 sequential requests, want 1 (keep-alive reuse)", got)
	}
}
