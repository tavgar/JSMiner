package scan

import (
	"math/rand"
	"net/http"
	"net/url"
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
// rejected requests it never adapts to — worse, a rate-limited response is an
// error page, so a page that would have yielded a secret is instead scanned as a
// 429 shell and its findings are lost. Staying under the limit is therefore not
// just politeness; it directly protects accuracy and secret recall.
//
// requestThrottle paces the shared HTTP path so the crawl stays under those
// limits. It works per host — a backoff learned against one host never slows an
// unrelated host, and each host is spaced by its own gap — and does three things:
//
//   - Proactive spacing. When a minimum inter-request gap is configured (via
//     SetRateLimit), consecutive requests to a host are spaced at least that far
//     apart. The default gap is zero, so single-target scans are unaffected
//     unless the user opts in.
//
//   - Budget-aware pre-emption. Servers that rate-limit almost always advertise
//     the remaining budget and its reset in response headers (the RateLimit-* /
//     X-RateLimit-* families and Retry-After). The throttle reads these on every
//     response and spreads the remaining requests across the reset window, so the
//     crawl slows down as it approaches the limit and never actually trips it —
//     preventing the rate-limit response before it happens rather than only
//     reacting after one. This is what keeps a rate-limited page from being seen
//     as an error shell instead of its real, secret-bearing content.
//
//   - Adaptive backoff. Whenever a response is a 429 (Too Many Requests) or 503
//     (Service Unavailable) the host's gap is multiplicatively widened and the
//     server's Retry-After hint — delta-seconds or HTTP-date — is honoured before
//     the next request is released. A run of clean responses decays the gap back
//     toward the configured base. Backoff is always on, even when no base gap is
//     set, so a scan that starts getting rate-limited slows itself down instead of
//     hammering a host that is already saying "stop".
//
// Optional jitter (SetRateLimitJitter) randomises each computed gap by a fraction
// so a crawl's requests do not form a perfectly regular cadence that some edge
// rate limiters treat as bot-like; it is off by default so paced scans stay
// deterministic unless opted in.
type requestThrottle struct {
	mu      sync.Mutex
	baseGap time.Duration // configured minimum per-host spacing (0 = no proactive spacing)
	maxGap  time.Duration // ceiling for adaptive backoff and honoured Retry-After / reset holds
	jitter  float64       // ± fraction applied to each computed gap (0 = none)

	hosts map[string]*hostThrottle // per-host pacing state, keyed by hostname

	// hostFloor is a per-host minimum inter-request gap that no amount of decay
	// drops below, used to honour a site's robots.txt Crawl-delay: the site has
	// stated how fast it is willing to be crawled, so the crawl never paces faster
	// than that against that host even when the global base gap is smaller. Keyed by
	// hostname; absent hosts have no floor.
	hostFloor map[string]time.Duration

	// sleep is the blocking wait, indirected so tests can observe scheduling
	// without spending wall-clock time. now and rnd are likewise injectable.
	sleep func(time.Duration)
	now   func() time.Time
	rnd   func() float64
}

// hostThrottle is the per-host pacing state: its current gap, the earliest instant
// its next request may start, and its recent clean-response streak for gap decay.
type hostThrottle struct {
	curGap      time.Duration
	next        time.Time
	lastBackoff time.Time
	ok          int
}

// Adaptive-backoff tuning. These govern how aggressively the throttle reacts to
// a rate-limit response and how quickly it recovers afterwards.
const (
	// throttleMinBackoff is the gap the throttle jumps to on the first 429/503
	// when no larger gap is already in effect, so backoff is meaningful even when
	// no proactive rate limit was configured.
	throttleMinBackoff = 500 * time.Millisecond

	// throttleDefaultMaxGap caps the adaptive gap, any honoured Retry-After and any
	// budget-based hold, so a hostile or mistaken hint cannot stall a scan
	// indefinitely.
	throttleDefaultMaxGap = 30 * time.Second

	// throttleDecayStreak is how many consecutive clean responses halve the gap,
	// easing the crawl back to full speed once the host stops rate-limiting.
	throttleDecayStreak = 5
)

// rateLimitRemainingHeaders and rateLimitResetHeaders are the response headers,
// in priority order, that advertise how many requests remain in the current
// window and when it resets. They cover the IETF draft RateLimit-* fields and the
// widespread X-RateLimit-* / X-Rate-Limit-* vendor variants (GitHub, Twitter,
// Cloudflare, and others).
var (
	rateLimitRemainingHeaders = []string{"RateLimit-Remaining", "X-RateLimit-Remaining", "X-Rate-Limit-Remaining"}
	rateLimitResetHeaders     = []string{"RateLimit-Reset", "X-RateLimit-Reset", "X-Rate-Limit-Reset"}
)

func newRequestThrottle() *requestThrottle {
	return &requestThrottle{
		maxGap: throttleDefaultMaxGap,
		hosts:  make(map[string]*hostThrottle),
		sleep:  time.Sleep,
		now:    time.Now,
		rnd:    rand.Float64,
	}
}

// globalThrottle paces every request issued through fetchURLResponseMethod.
var globalThrottle = newRequestThrottle()

// host returns the pacing state for hostname h, creating it (seeded with the
// configured base gap so proactive spacing applies from the first request) on
// first use. The caller must hold t.mu.
func (t *requestThrottle) host(h string) *hostThrottle {
	hs := t.hosts[h]
	if hs == nil {
		hs = &hostThrottle{curGap: t.baseGapFor(h)}
		t.hosts[h] = hs
	}
	return hs
}

// baseGapFor returns the effective base gap for host h: the larger of the global
// configured base gap and any per-host robots.txt Crawl-delay floor. It is the
// floor that adaptive decay eases back toward, so a host's pacing never recovers
// below its stated Crawl-delay. The caller holds t.mu.
func (t *requestThrottle) baseGapFor(h string) time.Duration {
	g := t.baseGap
	if f := t.hostFloor[h]; f > g {
		g = f
	}
	return g
}

// hostOf extracts the hostname the throttle keys on from a raw URL. An unparseable
// URL collapses to the empty key, which simply shares one pacing bucket.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// SetRateLimit configures proactive request spacing for the shared HTTP path,
// expressed as a maximum number of requests per second per host. A value <= 0
// disables proactive spacing (the default), leaving only adaptive backoff and
// budget-aware pre-emption active. It is safe to call before a scan starts.
func SetRateLimit(perSecond float64) {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if perSecond <= 0 {
		globalThrottle.baseGap = 0
	} else {
		globalThrottle.baseGap = time.Duration(float64(time.Second) / perSecond)
	}
	// Raise any host already below the new floor so the change takes effect at once.
	for _, hs := range globalThrottle.hosts {
		if hs.curGap < globalThrottle.baseGap {
			hs.curGap = globalThrottle.baseGap
		}
	}
}

// SetHostRateFloor records a minimum inter-request gap for a single host, used to
// honour that site's robots.txt Crawl-delay. The floor is combined with (never
// lowers) the global base gap and is the level adaptive decay eases back toward,
// so the crawl never paces faster than the site asked for that host. A larger
// floor replaces a smaller one; a non-positive gap is ignored. Safe to call before
// or during a scan.
func SetHostRateFloor(host string, gap time.Duration) {
	if gap <= 0 {
		return
	}
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if globalThrottle.hostFloor == nil {
		globalThrottle.hostFloor = make(map[string]time.Duration)
	}
	if gap > globalThrottle.hostFloor[host] {
		globalThrottle.hostFloor[host] = gap
	}
	// Apply immediately so the floor takes effect on the very next request.
	hs := globalThrottle.host(host)
	if hs.curGap < gap {
		hs.curGap = gap
	}
}

// SetMaxBackoff overrides the ceiling on the adaptive gap and any honoured
// Retry-After / reset hold. A non-positive value restores the default.
func SetMaxBackoff(d time.Duration) {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if d <= 0 {
		d = throttleDefaultMaxGap
	}
	globalThrottle.maxGap = d
}

// SetRateLimitJitter sets the fraction (e.g. 0.2 for ±20%) by which each computed
// inter-request gap is randomised, breaking up the perfectly regular cadence a
// paced crawl would otherwise produce. A non-positive value disables jitter (the
// default). Values above 1 are clamped to 1.
func SetRateLimitJitter(fraction float64) {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	globalThrottle.jitter = fraction
}

// ResetThrottle clears all accumulated per-host pacing state, restoring the
// throttle to its configured base gap. It exists mainly so tests start from a
// known state.
func ResetThrottle() {
	globalThrottle.mu.Lock()
	defer globalThrottle.mu.Unlock()
	globalThrottle.hosts = make(map[string]*hostThrottle)
	globalThrottle.hostFloor = nil
}

// wait blocks until the throttle permits the next request to the empty-key host.
// It is retained for callers and tests that do not track a host.
func (t *requestThrottle) wait() { t.waitHost("") }

// waitHost blocks until the throttle permits the next request to host h to start,
// and reserves the following slot. It is called immediately before each outbound
// request.
func (t *requestThrottle) waitHost(h string) {
	t.mu.Lock()
	hs := t.host(h)
	now := t.now()
	wakeAt := hs.next
	if wakeAt.Before(now) {
		wakeAt = now
	}
	// Reserve the next slot a (jittered) gap after this request is released so a
	// second caller cannot slip in ahead of the configured spacing.
	hs.next = wakeAt.Add(t.jittered(hs.curGap))
	delay := wakeAt.Sub(now)
	t.mu.Unlock()

	if delay > 0 {
		vlog(3, "[throttle] waiting %s before next request to %q", delay.Round(time.Millisecond), h)
		t.sleep(delay)
	}
}

// jittered applies the configured jitter fraction to a gap. The caller holds t.mu.
func (t *requestThrottle) jittered(gap time.Duration) time.Duration {
	if t.jitter <= 0 || gap <= 0 {
		return gap
	}
	// Symmetric ±jitter: rnd() in [0,1) maps to a factor in [1-jitter, 1+jitter).
	factor := 1 + t.jitter*(t.rnd()*2-1)
	out := time.Duration(float64(gap) * factor)
	if out < 0 {
		out = 0
	}
	return out
}

// isThrottleStatus reports whether a status code is a server rate-limit / overload
// signal the throttle should back off from.
func isThrottleStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// observe records the outcome of a Go-client request to the empty-key host.
func (t *requestThrottle) observe(resp *http.Response, err error) { t.observeHost("", resp, err) }

// observeHost records the outcome of a request to host h so the throttle can
// adapt: a 429/503 widens the gap and pushes the next-allowed instant out
// (honouring Retry-After); any other response has its advertised rate-limit budget
// read so the throttle can pre-emptively spread the remaining requests across the
// reset window; and a run of clean 2xx/3xx responses decays the gap back toward
// the base.
func (t *requestThrottle) observeHost(h string, resp *http.Response, err error) {
	// A transport error carries no rate-limit signal, so leave the gap unchanged.
	if err != nil || resp == nil {
		return
	}
	if isThrottleStatus(resp.StatusCode) {
		t.noteThrottledHost(h, resp.StatusCode, resp.Header.Get("Retry-After"))
		return
	}
	// Pre-empt the limit from the server's advertised budget on any other status
	// (including a 403 that carries rate-limit headers or a Retry-After).
	t.applyBudget(h, resp.Header)
	// Only genuine success earns a decay back toward the base gap.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		t.decay(h)
	}
}

// applyBudget reads the advertised rate-limit budget from a response's headers and
// pre-emptively spaces the host's next request so the remaining allowance is
// spread across the window until it resets — the crawl slows as it nears the limit
// and never actually trips it. A Retry-After on a non-429/503 response is honoured
// too. It only ever pushes the next-allowed instant later, never earlier, so it
// cannot speed a crawl past its configured spacing.
func (t *requestThrottle) applyBudget(h string, header http.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var hold time.Duration

	// A Retry-After outside a 429/503 (some gateways send it with 403) still means
	// "wait this long".
	if ra := parseRetryAfter(header.Get("Retry-After"), t.now); ra > 0 {
		hold = ra
	}

	remStr := firstHeaderValue(header, rateLimitRemainingHeaders)
	if remStr != "" {
		if rem, err := strconv.Atoi(strings.TrimSpace(remStr)); err == nil {
			if d := t.budgetSpacing(rem, firstHeaderValue(header, rateLimitResetHeaders)); d > hold {
				hold = d
			}
		}
	}

	if hold <= 0 {
		return
	}
	if hold > t.maxGap {
		hold = t.maxGap
	}
	hs := t.host(h)
	if until := t.now().Add(hold); until.After(hs.next) {
		hs.next = until
		vlog(3, "[throttle] budget-aware hold %s before next request to %q", hold.Round(time.Millisecond), h)
	}
}

// budgetSpacing computes how long to wait before the next request given the
// remaining allowance and the raw reset header. With none remaining it holds until
// the window resets; otherwise it spreads the remaining requests evenly across the
// time left in the window, so the crawl arrives at the reset with budget to spare
// rather than slamming into the limit. The caller holds t.mu.
func (t *requestThrottle) budgetSpacing(remaining int, resetRaw string) time.Duration {
	resetAt, ok := parseResetTime(resetRaw, t.now)
	if !ok {
		// Budget is exhausted but we do not know the window: apply a conservative
		// cool-down so we do not immediately trip the limit.
		if remaining <= 0 {
			return throttleMinBackoff
		}
		return 0
	}
	window := resetAt.Sub(t.now())
	if window <= 0 {
		return 0
	}
	if remaining <= 0 {
		return window
	}
	return window / time.Duration(remaining+1)
}

// noteThrottled folds a rate-limit response for the empty-key host into its gap.
func (t *requestThrottle) noteThrottled(status int, retryAfter string) {
	t.noteThrottledHost("", status, retryAfter)
}

// noteThrottledHost folds a rate-limit response into host h's adaptive gap: it
// doubles the gap (up to the ceiling) and pushes the next-allowed instant out,
// honouring the server's Retry-After hint. It is reachable from the render path so
// a 429/503 seen by headless Chrome — whose sub-resource fetches never pass
// through observe — still slows the rest of the scan, making the throttle a
// rate-limit signal shared across the Go and browser request paths. retryAfter is
// the raw header value ("" when absent).
func (t *requestThrottle) noteThrottledHost(h string, status int, retryAfter string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	hs := t.host(h)
	hs.ok = 0
	now := t.now()
	// Several requests may already be in flight when the first 429/503 arrives.
	// Their responses describe one burst, not independent failures at progressively
	// slower rates; multiplying the gap for every member of that burst can jump
	// straight from 500ms to the 30s ceiling. Coalesce signals that arrive within
	// the current backoff window. A later response, after the crawler actually
	// waited at that rate, is new evidence and escalates normally.
	coalesced := !hs.lastBackoff.IsZero() &&
		!now.Before(hs.lastBackoff) &&
		now.Sub(hs.lastBackoff) < hs.curGap
	if !coalesced {
		next := hs.curGap * 2
		if next < throttleMinBackoff {
			next = throttleMinBackoff
		}
		if next > t.maxGap {
			next = t.maxGap
		}
		hs.curGap = next
		hs.lastBackoff = now
	}

	resumeAt := now.Add(hs.curGap)
	if ra := parseRetryAfter(retryAfter, t.now); ra > 0 {
		if ra > t.maxGap {
			ra = t.maxGap
		}
		if until := now.Add(ra); until.After(resumeAt) {
			resumeAt = until
		}
	}
	if resumeAt.After(hs.next) {
		hs.next = resumeAt
	}
	if coalesced {
		vlog(2, "[throttle] %d from %q -> coalesced with current burst, gap remains %s", status, h, hs.curGap.Round(time.Millisecond))
	} else {
		vlog(2, "[throttle] %d from %q -> backing off, gap now %s", status, h, hs.curGap.Round(time.Millisecond))
	}
}

// decay eases host h's adaptive gap back toward the base after a run of clean
// responses, so the crawl returns to full speed once the host stops rate-limiting.
func (t *requestThrottle) decay(h string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	hs := t.host(h)
	base := t.baseGapFor(h)
	if hs.curGap <= base {
		return
	}
	hs.ok++
	if hs.ok >= throttleDecayStreak {
		hs.curGap /= 2
		if hs.curGap < base {
			hs.curGap = base
		}
		hs.ok = 0
		vlog(3, "[throttle] %q recovered -> gap now %s", h, hs.curGap.Round(time.Millisecond))
	}
}

// firstHeaderValue returns the value of the first present header among names,
// matched case-insensitively (http.Header.Get canonicalises the key).
func firstHeaderValue(header http.Header, names []string) string {
	for _, n := range names {
		if v := header.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// parseResetTime resolves a rate-limit reset header to an absolute instant. The
// value is either delta-seconds until the window resets (the IETF draft, and most
// X-RateLimit-Reset uses), an absolute Unix timestamp (GitHub-style), or an
// HTTP-date. now is injected so tests are deterministic.
func parseResetTime(v string, now func() time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return now(), true
		}
		// A value large enough to be a plausible epoch (after 2001) is an absolute
		// timestamp; anything smaller is a delta in seconds from now.
		if secs > 1_000_000_000 {
			return time.Unix(secs, 0), true
		}
		return now().Add(time.Duration(secs) * time.Second), true
	}
	if ts, err := http.ParseTime(v); err == nil {
		return ts, true
	}
	return time.Time{}, false
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
