package scan

import (
	"testing"
	"time"
)

// TestSetHTTPTimeoutWiring verifies that SetHTTPTimeout is honoured by the shared
// HTTP client — the timeout was previously hardcoded, leaving HTTPClientTimeout
// dead — and that a non-positive value restores the default.
func TestSetHTTPTimeoutWiring(t *testing.T) {
	orig := HTTPClientTimeout
	defer func() {
		HTTPClientTimeout = orig
	}()

	SetHTTPTimeout(45)
	if HTTPClientTimeout != 45*time.Second {
		t.Fatalf("HTTPClientTimeout = %v, want 45s", HTTPClientTimeout)
	}
	if c := newHTTPClient(); c.Timeout != 45*time.Second {
		t.Fatalf("client Timeout = %v, want 45s", c.Timeout)
	}

	SetHTTPTimeout(0)
	if HTTPClientTimeout != 10*time.Second {
		t.Fatalf("SetHTTPTimeout(0) = %v, want default 10s", HTTPClientTimeout)
	}
	if c := newHTTPClient(); c.Timeout != 10*time.Second {
		t.Fatalf("client Timeout after reset = %v, want 10s", c.Timeout)
	}
}
