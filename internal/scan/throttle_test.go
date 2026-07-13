package scan

import (
	"net/http"
	"testing"
	"time"
)

// newTestThrottle builds a throttle with a virtual clock so scheduling can be
// asserted without spending wall-clock time. Returned advance() moves the clock
// forward; slept records every non-zero sleep the throttle requests, and also
// advances the clock by that amount (mirroring real time passing).
func newTestThrottle() (*requestThrottle, *[]time.Duration, func(time.Duration)) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	var slept []time.Duration
	t := newRequestThrottle()
	t.now = func() time.Time { return cur }
	t.sleep = func(d time.Duration) {
		slept = append(slept, d)
		cur = cur.Add(d)
	}
	advance := func(d time.Duration) { cur = cur.Add(d) }
	return t, &slept, advance
}

func resp(status int, retryAfter string) *http.Response {
	h := http.Header{}
	if retryAfter != "" {
		h.Set("Retry-After", retryAfter)
	}
	return &http.Response{StatusCode: status, Header: h}
}

func TestThrottleNoProactiveGapByDefault(t *testing.T) {
	th, slept, _ := newTestThrottle()
	for i := 0; i < 5; i++ {
		th.wait()
		th.observe(resp(200, ""), nil)
	}
	if len(*slept) != 0 {
		t.Fatalf("expected no sleeps with zero base gap, got %v", *slept)
	}
}

func TestThrottleProactiveSpacing(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.baseGap = 200 * time.Millisecond
	th.curGap = th.baseGap

	// First request goes immediately; each subsequent one is spaced by baseGap.
	for i := 0; i < 4; i++ {
		th.wait()
		th.observe(resp(200, ""), nil)
	}
	// 4 requests => 3 inter-request gaps.
	if len(*slept) != 3 {
		t.Fatalf("expected 3 spacing sleeps, got %d: %v", len(*slept), *slept)
	}
	for _, d := range *slept {
		if d != 200*time.Millisecond {
			t.Fatalf("expected 200ms spacing, got %s", d)
		}
	}
}

func TestThrottleBacksOffOn429(t *testing.T) {
	th, slept, _ := newTestThrottle()

	// A 429 with no base gap should jump the gap to the minimum backoff and make
	// the next request wait at least that long.
	th.wait()
	th.observe(resp(429, ""), nil)
	if th.curGap != throttleMinBackoff {
		t.Fatalf("expected curGap %s after first 429, got %s", throttleMinBackoff, th.curGap)
	}
	th.wait()
	if len(*slept) != 1 || (*slept)[0] < throttleMinBackoff {
		t.Fatalf("expected a >= %s wait after 429, got %v", throttleMinBackoff, *slept)
	}

	// A second 429 doubles the gap.
	th.observe(resp(429, ""), nil)
	if th.curGap != 2*throttleMinBackoff {
		t.Fatalf("expected curGap to double to %s, got %s", 2*throttleMinBackoff, th.curGap)
	}
}

func TestThrottleHonoursRetryAfterSeconds(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.wait()
	th.observe(resp(503, "5"), nil)
	th.wait()
	if len(*slept) != 1 {
		t.Fatalf("expected one wait, got %v", *slept)
	}
	// Retry-After of 5s exceeds the minimum backoff, so it governs the wait.
	if (*slept)[0] < 5*time.Second {
		t.Fatalf("expected wait to honour Retry-After 5s, got %s", (*slept)[0])
	}
}

func TestThrottleRetryAfterCappedByMaxGap(t *testing.T) {
	th, slept, _ := newTestThrottle()
	th.maxGap = 10 * time.Second
	th.wait()
	th.observe(resp(429, "3600"), nil) // server asks for an hour
	th.wait()
	if len(*slept) != 1 {
		t.Fatalf("expected one wait, got %v", *slept)
	}
	if (*slept)[0] > 10*time.Second {
		t.Fatalf("expected Retry-After capped at maxGap 10s, got %s", (*slept)[0])
	}
}

func TestThrottleDecaysAfterCleanResponses(t *testing.T) {
	th, _, _ := newTestThrottle()
	th.baseGap = 100 * time.Millisecond
	th.curGap = th.baseGap

	// Drive the gap up with a couple of 429s.
	th.observe(resp(429, ""), nil)
	th.observe(resp(429, ""), nil)
	elevated := th.curGap
	if elevated <= th.baseGap {
		t.Fatalf("expected elevated gap after 429s, got %s", elevated)
	}

	// A full streak of clean responses halves the gap once.
	for i := 0; i < throttleDecayStreak; i++ {
		th.observe(resp(200, ""), nil)
	}
	if th.curGap != elevated/2 {
		t.Fatalf("expected gap to halve to %s after a clean streak, got %s", elevated/2, th.curGap)
	}
}

func TestThrottleTransportErrorDoesNotDecay(t *testing.T) {
	th, _, _ := newTestThrottle()
	th.observe(resp(429, ""), nil)
	elevated := th.curGap
	// Transport errors carry no rate-limit signal and must not be counted as a
	// clean response that decays the backoff.
	for i := 0; i < throttleDecayStreak*2; i++ {
		th.observe(nil, http.ErrHandlerTimeout)
	}
	if th.curGap != elevated {
		t.Fatalf("expected gap unchanged by transport errors, got %s (was %s)", th.curGap, elevated)
	}
}

func TestNoteThrottledBacksOffLikeObserve(t *testing.T) {
	th, slept, _ := newTestThrottle()
	// The render path feeds a browser-observed 429 in via noteThrottled; it must
	// widen the gap and delay the next request just as a Go-path 429 would.
	th.noteThrottled(429, "2")
	if th.curGap != throttleMinBackoff {
		t.Fatalf("expected curGap %s, got %s", throttleMinBackoff, th.curGap)
	}
	th.wait()
	if len(*slept) != 1 || (*slept)[0] < 2*time.Second {
		t.Fatalf("expected a >= 2s wait honouring Retry-After, got %v", *slept)
	}
}

func TestObserveDelegatesToNoteThrottled(t *testing.T) {
	th, _, _ := newTestThrottle()
	th.observe(resp(503, ""), nil)
	if th.curGap != throttleMinBackoff {
		t.Fatalf("expected observe(503) to back off to %s, got %s", throttleMinBackoff, th.curGap)
	}
}

func TestRetryAfterFromHeaders(t *testing.T) {
	h := map[string]interface{}{"Content-Type": "text/html", "retry-after": "9"}
	if got := retryAfterFromHeaders(h); got != "9" {
		t.Fatalf("expected case-insensitive Retry-After=9, got %q", got)
	}
	if got := retryAfterFromHeaders(map[string]interface{}{}); got != "" {
		t.Fatalf("expected empty for missing header, got %q", got)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	future := now.Add(30 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfter(future, func() time.Time { return now })
	// HTTP-date has second granularity, so allow a small rounding slack.
	if got < 29*time.Second || got > 31*time.Second {
		t.Fatalf("expected ~30s from HTTP-date, got %s", got)
	}
	if d := parseRetryAfter("", func() time.Time { return now }); d != 0 {
		t.Fatalf("expected 0 for empty header, got %s", d)
	}
	if d := parseRetryAfter("-5", func() time.Time { return now }); d != 0 {
		t.Fatalf("expected 0 for negative seconds, got %s", d)
	}
}
