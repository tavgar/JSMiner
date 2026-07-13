package scan

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A crawl can fire many requests against one host in a tight loop: each page is
// fetched, rendered, probed with every method in RequestMethods, and — the first
// time a directory level or (method, level) pair is seen — calibrated with
// several random probes, on top of any parameter replays and path permutations.
// Back-to-back that easily trips a server's rate limiter, after which every
// further request comes back 429/503 and the crawl wastes its page budget on
// rejected requests it never adapts to.
//
// requestThrottle paces the shared HTTP path so the crawl stays under those
// limits. It does two things:
//
//   - Proactive spacing. When a minimum inter-request gap is configured (via
//     SetRateLimit), consecutive requests are spaced at least that far apart.
//     The default gap is zero, so single-target scans are unaffected unless the
//     user opts in.
//
//   - Adaptive backoff. Whenever a response is a 429 (Too Many Requests) or 503
//     (Service Unavailable) the current gap is multiplicatively widened and the
//     server's Retry-After hint — delta-seconds or HTTP-date — is honoured before
//     the next request is released. A run of clean responses decays the gap back
//     toward the configured base. Backoff is always on, even when no base gap is
//     set, so a scan that starts getting rate-limited slows itself down instead of
//     hammering a host that is already saying "stop".
type requestThrottle struct {
	mu      sync.Mutex
	baseGap time.Duration // configured minimum spacing (0 = no proactive spacing)
	curGap  time.Duration // current adaptive spacing, always >= baseGap
	maxGap  time.Duration // ceiling for adaptive backoff and honoured Retry-After
	next    time.Time     // earliest instant the next request may start
	ok      int           // consecutive non-throttled responses, for gap decay

	// sleep is the blocking wait, indirected so tests can observe scheduling
	// without spending wall-clock time.
	sleep func(time.Duration)
	now    func() time.Time
}

// Adaptive-backoff tuning. These govern how aggressively the throttle reacts to
// a rate-limit response and how quickly it recovers afterwards.
const (
	// throttleMinBackoff is the gap the throttle jumps to on the first 429/503
	// when no larger gap is already in effect, so backoff is meaningful even when
	// no proactive rate limit was configured.
	throttleMinBackoff = 500 * time.Millisecond

	// throttleDefaultMaxGap caps both the adaptive gap and any honoured
	// Retry-After, so a hostile or mistaken hint cannot stall a scan indefinitely.
	throttleDefaultMaxGap = 30 * time.Second

	// throttleDecayStreak is how many consecutive clean responses halve the gap,
	// easing the crawl back to full speed once the host stops rate-limiting.
	throttleDecayStreak = 5
)

func newRequestThrottle() *requestThrottle {
	return &requestThrottle{
		maxGap: throttleDefaultMaxGap,
		sleep:  time.Sleep,
		now:    time.Now,
	}
}

// globalThrottle paces every request issued through fetchURLResponseMethod.
var globalThrottle = newRequestThrottle()

// SetRateLimit configures proactive request spacing for the shared HTTP path,
// expressed as a maximum number of requests per second across the whole scan. A
// value <= 0 disables proactive spacing (the default), leaving only adaptive
// backoff active. It is safe to call before a scan starts.
func SetRateLimit(perSecond float64) {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if perSecond <= 0 {
		globalThrottle.baseGap = 0
	} else {
		globalThrottle.baseGap = time.Duration(float64(time.Second) / perSecond)
	}
	if globalThrottle.curGap < globalThrottle.baseGap {
		globalThrottle.curGap = globalThrottle.baseGap
	}
}

// SetMaxBackoff overrides the ceiling on the adaptive gap and any honoured
// Retry-After. A non-positive value restores the default.
func SetMaxBackoff(d time.Duration) {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if d <= 0 {
		d = throttleDefaultMaxGap
	}
	globalThrottle.maxGap = d
}

// ResetThrottle clears any accumulated adaptive backoff, restoring the throttle
// to its configured base gap. It exists mainly so tests start from a known state.
func ResetThrottle() {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	globalThrottle.curGap = globalThrottle.baseGap
	globalThrottle.next = time.Time{}
	globalThrottle.ok = 0
}

// wait blocks until the throttle permits the next request to start, and reserves
// the following slot. It is called immediately before each outbound request.
func (t *requestThrottle) wait() {
	t.mu.Lock()
	now := t.now()
	wakeAt := t.next
	if wakeAt.Before(now) {
		wakeAt = now
	}
	// Reserve the next slot curGap after this request is released so a second
	// caller cannot slip in ahead of the configured spacing.
	t.next = wakeAt.Add(t.curGap)
	delay := wakeAt.Sub(now)
	t.mu.Unlock()

	if delay > 0 {
		vlog(3, "[throttle] waiting %s before next request", delay.Round(time.Millisecond))
		t.sleep(delay)
	}
}

// isThrottleStatus reports whether a status code is a server rate-limit / overload
// signal the throttle should back off from.
func isThrottleStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// observe records the outcome of a Go-client request so the throttle can adapt: a
// 429/503 widens the gap and pushes the next-allowed instant out (honouring
// Retry-After), while a run of clean responses decays the gap back toward the base.
func (t *requestThrottle) observe(resp *http.Response, err error) {
	if err == nil && resp != nil && isThrottleStatus(resp.StatusCode) {
		t.noteThrottled(resp.StatusCode, resp.Header.Get("Retry-After"))
		return
	}
	// A transport error carries no rate-limit signal, so leave the gap unchanged;
	// only genuine clean responses earn a decay back toward the base gap.
	if err != nil || resp == nil {
		return
	}
	t.decay()
}

// noteThrottled folds a rate-limit response into the adaptive gap: it doubles the
// gap (up to the ceiling) and pushes the next-allowed instant out, honouring the
// server's Retry-After hint. It is exported to the render path so a 429/503 seen
// by headless Chrome — whose sub-resource fetches never pass through observe —
// still slows the rest of the scan, making the throttle a rate-limit signal
// shared across the Go and browser request paths. retryAfter is the raw header
// value ("" when absent).
func (t *requestThrottle) noteThrottled(status int, retryAfter string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ok = 0
	next := t.curGap * 2
	if next < throttleMinBackoff {
		next = throttleMinBackoff
	}
	if next > t.maxGap {
		next = t.maxGap
	}
	t.curGap = next

	resumeAt := t.now().Add(t.curGap)
	if ra := parseRetryAfter(retryAfter, t.now); ra > 0 {
		if ra > t.maxGap {
			ra = t.maxGap
		}
		if until := t.now().Add(ra); until.After(resumeAt) {
			resumeAt = until
		}
	}
	if resumeAt.After(t.next) {
		t.next = resumeAt
	}
	vlog(2, "[throttle] %d from server -> backing off, gap now %s", status, t.curGap.Round(time.Millisecond))
}

// decay eases the adaptive gap back toward the base after a run of clean
// responses, so the crawl returns to full speed once a host stops rate-limiting.
func (t *requestThrottle) decay() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.curGap <= t.baseGap {
		return
	}
	t.ok++
	if t.ok >= throttleDecayStreak {
		t.curGap /= 2
		if t.curGap < t.baseGap {
			t.curGap = t.baseGap
		}
		t.ok = 0
		vlog(3, "[throttle] recovered -> gap now %s", t.curGap.Round(time.Millisecond))
	}
}

// parseRetryAfter interprets a Retry-After header value, which is either a
// non-negative number of seconds or an HTTP-date. It returns the delay until the
// server says it will accept requests again, or zero when the value is absent,
// malformed or already in the past. now is injected so tests are deterministic.
func parseRetryAfter(v string, now func() time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if ts, err := http.ParseTime(v); err == nil {
		if d := ts.Sub(now()); d > 0 {
			return d
		}
	}
	return 0
}
