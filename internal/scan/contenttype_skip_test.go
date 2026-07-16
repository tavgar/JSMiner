package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestScanSkipsBinaryContentType verifies the crawl bails on a response whose
// Content-Type is binary even when the URL carries no telltale extension — so an
// extensionless /download/report that returns application/pdf or an image is not
// downloaded in full, scanned, or rendered. The same bytes served as JavaScript
// are still scanned, proving it is the Content-Type (not the body) that gates.
func TestScanSkipsBinaryContentType(t *testing.T) {
	// A valid-looking JWT sitting in the body of every response.
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJtYWluIjoxMjN9.binaryGateSignatureAAAA"
	body := "var token='" + secret + "';"

	mux := http.NewServeMux()
	serve := func(ct string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			io.WriteString(w, body)
		}
	}
	// Extensionless URLs whose only binary signal is the Content-Type.
	mux.HandleFunc("/download/report", serve("application/pdf"))
	mux.HandleFunc("/assets/hero", serve("image/png"))
	mux.HandleFunc("/api/script", serve("application/javascript"))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Safe mode off so extensionless JS is scanned by content; this isolates the
	// Content-Type gate as the only thing that can suppress a match.
	e := NewExtractor(false, false)

	hasSecret := func(u string) bool {
		ms, err := e.ScanURL(u, false, false, false)
		if err != nil {
			t.Fatalf("scan %s: %v", u, err)
		}
		for _, m := range ms {
			if m.Value == secret {
				return true
			}
		}
		return false
	}

	if hasSecret(ts.URL + "/download/report") {
		t.Error("application/pdf response was scanned; should be skipped by Content-Type")
	}
	if hasSecret(ts.URL + "/assets/hero") {
		t.Error("image/png response was scanned; should be skipped by Content-Type")
	}
	if !hasSecret(ts.URL + "/api/script") {
		t.Error("application/javascript response was not scanned; the gate is too aggressive")
	}
}
