package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test that FetchURL sets the User-Agent header on requests
func TestFetchURLSetsUserAgent(t *testing.T) {
	var ua string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		io.WriteString(w, "ok")
	}))
	defer ts.Close()

	SetExtraHeaders(nil)
	rc, err := FetchURL(ts.URL)
	if err != nil {
		t.Fatalf("FetchURL returned error: %v", err)
	}
	rc.Close()

	if ua != defaultUserAgent {
		t.Fatalf("expected User-Agent %q, got %q", defaultUserAgent, ua)
	}
}

// Test that FetchURL uses extra headers provided via SetExtraHeaders
func TestFetchURLExtraHeaders(t *testing.T) {
	var hv string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hv = r.Header.Get("X-Test")
		io.WriteString(w, "ok")
	}))
	defer ts.Close()

	h := http.Header{}
	h.Set("X-Test", "yes")
	SetExtraHeaders(h)
	rc, err := FetchURL(ts.URL)
	if err != nil {
		t.Fatalf("FetchURL returned error: %v", err)
	}
	rc.Close()

	if hv != "yes" {
		t.Fatalf("expected header X-Test yes, got %q", hv)
	}
}

// Test that FetchURL can skip TLS verification when configured
func TestFetchURLSkipTLSVerify(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer ts.Close()

	SetSkipTLSVerification(false)
	if _, err := FetchURL(ts.URL); err == nil {
		t.Fatalf("expected TLS error when verification enabled")
	}

	SetSkipTLSVerification(true)
	rc, err := FetchURL(ts.URL)
	if err != nil {
		t.Fatalf("FetchURL returned error with skip verify: %v", err)
	}
	rc.Close()
	SetSkipTLSVerification(true)
}
