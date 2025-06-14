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

	rc, err := FetchURL(ts.URL)
	if err != nil {
		t.Fatalf("FetchURL returned error: %v", err)
	}
	rc.Close()

	if ua != defaultUserAgent {
		t.Fatalf("expected User-Agent %q, got %q", defaultUserAgent, ua)
	}
}
