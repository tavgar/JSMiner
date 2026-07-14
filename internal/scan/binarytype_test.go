package scan

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsBinaryContentType(t *testing.T) {
	binary := []string{
		"image/png", "image/svg+xml", "audio/mpeg", "video/mp4", "font/woff2",
		"application/pdf", "application/zip", "application/gzip",
		"IMAGE/JPEG", "image/png; charset=binary", " application/pdf ",
	}
	for _, ct := range binary {
		if !isBinaryContentType(ct) {
			t.Errorf("isBinaryContentType(%q) = false, want true", ct)
		}
	}

	// Anything that can hold a secret or endpoint — including the ambiguous
	// octet-stream and an absent type — must never be skipped.
	textual := []string{
		"", "text/html", "text/plain", "application/javascript",
		"text/javascript", "application/json", "application/xml", "text/css",
		"application/octet-stream", "application/octet-stream; charset=utf-8",
	}
	for _, ct := range textual {
		if isBinaryContentType(ct) {
			t.Errorf("isBinaryContentType(%q) = true, want false", ct)
		}
	}
}

// TestScanURLSkipsBinaryContentType verifies scanURL does not scan a response
// served with a binary Content-Type, even when its bytes would otherwise match a
// rule — an extensionless URL that returns an image must not be mined as text.
func TestScanURLSkipsBinaryContentType(t *testing.T) {
	resetSharedClient()
	defer resetSharedClient()
	SetSkipTLSVerification(true)
	ResetThrottle()

	// A body that clearly matches an endpoint rule, so a non-skip would show up.
	const body = `{"api":"https://api.example.com/v1/users","k":"secret"}`

	binary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte(body))
	}))
	defer binary.Close()

	textual := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(body))
	}))
	defer textual.Close()

	e := NewExtractor(false, false)

	// Use a .js path so endpoint extraction runs; the skip is driven by the binary
	// Content-Type, not the URL, so the .js extension does not save the binary case.
	got, err := e.ScanURL(binary.URL+"/app.js", true, false, false)
	if err != nil {
		t.Fatalf("scan of binary response errored: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("binary response was scanned, got %d match(es): %+v", len(got), got)
	}

	// Control: the identical body under a JS content-type is scanned, proving the
	// skip — not some other filter — is what suppressed the binary case.
	ctrl, err := e.ScanURL(textual.URL+"/app.js", true, false, false)
	if err != nil {
		t.Fatalf("scan of JS response errored: %v", err)
	}
	if len(ctrl) == 0 {
		t.Fatal("control JS response yielded no matches; test cannot distinguish the skip")
	}
}
