package scan

import (
	"net/http"
	"testing"
	"time"
)

// respRL builds a response carrying arbitrary rate-limit headers.
func respRL(status int, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// TestBudgetSpreadsRemainingAcrossWindow verifies the throttle reads an advertised
// rate-limit budget and paces the next request so the remaining allowance is
// spread across the reset window — pre-empting the limit instead of tripping it.
func TestBudgetSpreadsRemainingAcrossWindow(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.maxGap = 60 * time.Second

	th.wait() // first request goes immediately
	// 4 requests left, window resets in 10s -> next request must wait 10/(4+1)=2s.
	th.observe(respRL(200, map[string]string{
		"RateLimit-Remaining": "4",
		"RateLimit-Reset":     "10",
	}), nil)
	th.wait()

	if len(*slept) != 1 || (*slept)[0] != 2*time.Second {
		t.Fatalf("expected a single 2s budget-spread wait, got %v", *slept)
	}
}

// TestBudgetExhaustedHoldsUntilReset verifies that with no requests remaining the
// throttle holds until the window resets rather than firing into a certain 429.
func TestBudgetExhaustedHoldsUntilReset(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.maxGap = 60 * time.Second

	th.wait()
	th.observe(respRL(200, map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     "8",
	}), nil)
	th.wait()

	if len(*slept) != 1 || (*slept)[0] != 8*time.Second {
		t.Fatalf("expected an 8s hold until reset, got %v", *slept)
	}
}

// TestBudgetHoldCappedByMaxGap verifies a very distant reset cannot stall the
// scan past the configured ceiling.
func TestBudgetHoldCappedByMaxGap(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.maxGap = 5 * time.Second

	th.wait()
	th.observe(respRL(200, map[string]string{
		"RateLimit-Remaining": "0",
		"RateLimit-Reset":     "3600",
	}), nil)
	th.wait()

	if len(*slept) != 1 || (*slept)[0] != 5*time.Second {
		t.Fatalf("expected the hold capped at maxGap 5s, got %v", *slept)
	}
}

// TestBudgetNoHeadersNoSlowdown verifies a plain response with no rate-limit
// headers imposes no spacing, so ordinary sites are never slowed.
func TestBudgetNoHeadersNoSlowdown(t *testing.T) {
	th, slept, _ := newTestThrottle()
	for i := 0; i < 4; i++ {
		th.wait()
		th.observe(respRL(200, nil), nil)
	}
	if len(*slept) != 0 {
		t.Fatalf("expected no spacing without rate-limit headers, got %v", *slept)
	}
}

// TestThrottlePerHostIsolation verifies a backoff learned against one host does
// not slow requests to an unrelated host.
func TestThrottlePerHostIsolation(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.maxGap = 60 * time.Second

	// Host A is told to back off for 10s.
	th.observeHost("a.example", resp(429, "10"), nil)

	// A request to host B must not be delayed by A's backoff.
	th.waitHost("b.example")
	if len(*slept) != 0 {
		t.Fatalf("host b was delayed by host a's backoff: %v", *slept)
	}

	// A request to host A must honour its backoff.
	th.waitHost("a.example")
	if len(*slept) != 1 || (*slept)[0] < 10*time.Second {
		t.Fatalf("expected host a to wait >= 10s, got %v", *slept)
	}
}

// TestThrottleJitter verifies the configured jitter fraction perturbs the spacing
// deterministically given a fixed RNG, at both extremes.
func TestThrottleJitter(t *testing.T) {
	for _, tc := range []struct {
		name string
		rnd  float64
		want time.Duration
	}{
		{"low", 0.0, 500 * time.Millisecond},  // factor 1 + 0.5*(0-1) = 0.5
		{"high", 1.0, 1500 * time.Millisecond}, // factor 1 + 0.5*(2-1) = 1.5
	} {
		t.Run(tc.name, func(t *testing.T) {
			th, slept, _ := newTestThrottle()
			th.baseGap = time.Second
			th.jitter = 0.5
			th.rnd = func() float64 { return tc.rnd }

			th.waitHost("h") // reserves next = now + jittered(1s)
			th.waitHost("h") // waits that jittered gap
			if len(*slept) != 1 || (*slept)[0] != tc.want {
				t.Fatalf("jitter rnd=%v: expected %s wait, got %v", tc.rnd, tc.want, *slept)
			}
		})
	}
}

func TestParseResetTime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }

	// Delta-seconds.
	if got, ok := parseResetTime("30", nowFn); !ok || !got.Equal(now.Add(30*time.Second)) {
		t.Fatalf("delta parse: got %v ok=%v", got, ok)
	}
	// Absolute Unix epoch.
	if got, ok := parseResetTime("1700000045", nowFn); !ok || !got.Equal(time.Unix(1700000045, 0)) {
		t.Fatalf("epoch parse: got %v ok=%v", got, ok)
	}
	// Zero / past resets to now.
	if got, ok := parseResetTime("0", nowFn); !ok || !got.Equal(now) {
		t.Fatalf("zero parse: got %v ok=%v", got, ok)
	}
	// HTTP-date.
	future := now.Add(20 * time.Second).UTC().Format(http.TimeFormat)
	if got, ok := parseResetTime(future, nowFn); !ok || got.Sub(now) < 19*time.Second {
		t.Fatalf("http-date parse: got %v ok=%v", got, ok)
	}
	// Empty / garbage.
	if _, ok := parseResetTime("", nowFn); ok {
		t.Fatal("empty should not parse")
	}
	if _, ok := parseResetTime("soon", nowFn); ok {
		t.Fatal("garbage should not parse")
	}
}
