package scan

import (
	"strings"
	"testing"
)

// endlessReader yields an unbounded stream of a single byte, standing in for a
// hostile or misconfigured server that never stops sending a response body.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// TestReadCappedBodyBounded verifies that a crawl's whole-body read refuses to
// buffer more than MaxResponseBodyBytes, so one endless response cannot exhaust
// memory and take the crawl down.
func TestReadCappedBodyBounded(t *testing.T) {
	data, err := readCappedBody(endlessReader{})
	if err != nil {
		t.Fatalf("readCappedBody returned error: %v", err)
	}
	if int64(len(data)) != int64(MaxResponseBodyBytes) {
		t.Fatalf("read %d bytes, want cap of %d", len(data), MaxResponseBodyBytes)
	}
}

// TestReadCappedBodyShort verifies that a normal, small body is returned intact
// so the cap never truncates legitimate content.
func TestReadCappedBodyShort(t *testing.T) {
	const body = "console.log('ok')"
	data, err := readCappedBody(strings.NewReader(body))
	if err != nil {
		t.Fatalf("readCappedBody returned error: %v", err)
	}
	if string(data) != body {
		t.Fatalf("read %q, want %q", data, body)
	}
}
