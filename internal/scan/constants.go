package scan

import "time"

// Network and buffer sizes
const (
	// MaxPostDataSize is the maximum POST data size that Chrome DevTools will capture
	MaxPostDataSize = 64 * 1024 // 64KB

	// InitialBufferSize is the initial size for scanner buffers
	InitialBufferSize = 64 * 1024 // 64KB

	// MaxBufferSize is the maximum size for scanner buffers.
	// Minified JS bundles are frequently emitted as a single multi-megabyte
	// line, so this must be large enough to hold an entire bundle as one token;
	// otherwise bufio.Scanner aborts with ErrTooLong and the whole file is
	// skipped. The scanner grows the buffer on demand up to this cap, so the
	// value is a ceiling, not a pre-allocation.
	MaxBufferSize = 64 * 1024 * 1024 // 64MB

	// MaxResponseBodyBytes caps how much of a fetched HTTP response the crawler
	// reads into memory before scanning it. A crawl fetches arbitrary, attacker-
	// influenced hosts at scale, so an unbounded read lets a single hostile or
	// misconfigured server that streams a body of any length exhaust the
	// scanner's memory and take the whole crawl down. The cap matches
	// MaxBufferSize — the scanner's own per-token ceiling — so bytes past it
	// would be dropped by the scanner anyway; bounding the read just refuses to
	// buffer them first.
	MaxResponseBodyBytes = MaxBufferSize
)

// Timeouts and delays
var (
	// RenderTimeout is the timeout for page rendering operations
	RenderTimeout = 15 * time.Second

	// RenderSleepDuration is the wait time for dynamic content to load
	RenderSleepDuration = 8 * time.Second

	// MaxExploreStates bounds how many additional application states the renderer
	// reaches by interacting with a page — clicking client-side navigation
	// controls and filling and submitting forms — beyond the initial load. A
	// single-page app hides most of its surface behind event handlers, so without
	// this the crawler sees only the shell it first rendered. Zero disables
	// interaction and restores the plain "render once" behaviour.
	MaxExploreStates = 12

	// ExploreSettleDuration is how long to wait after each interaction for the
	// resulting state to render (client-side route change, XHR-driven update or
	// form submission) before it is snapshotted. It is deliberately much shorter
	// than RenderSleepDuration, which is paid once for the initial load.
	ExploreSettleDuration = 1500 * time.Millisecond

	// HTTPClientTimeout is the timeout for HTTP requests
	HTTPClientTimeout = 10 * time.Second

	// SkipTLSVerification controls whether HTTPS certificate verification is skipped
	// Defaults to true so invalid certificates are accepted unless explicitly disabled
	SkipTLSVerification = true
)

// SetRenderSleepDuration allows customizing the sleep duration for page rendering
func SetRenderSleepDuration(seconds int) {
	RenderSleepDuration = time.Duration(seconds) * time.Second
}

// SetMaxExploreStates configures how many additional application states the
// renderer reaches through interaction. A non-positive value disables
// interaction-based exploration, rendering each page exactly once.
func SetMaxExploreStates(n int) {
	if n < 0 {
		n = 0
	}
	MaxExploreStates = n
}

// SetSkipTLSVerification configures whether HTTPS certificate verification should be skipped
func SetSkipTLSVerification(skip bool) {
	SkipTLSVerification = skip
}

// FetchRetries is how many extra attempts the shared HTTP fetch path makes when a
// request fails with a transport error — a connection reset, DNS blip or timeout,
// the kind of transient failure an enterprise crawl of thousands of requests hits
// routinely. Only safe, bodyless GET/HEAD/OPTIONS requests are retried, so active
// mutation probes and discovered parameter replays are never double-submitted
// against a target. Zero disables retries.
var FetchRetries = 2

// SetFetchRetries configures how many extra attempts a transient transport error
// earns on the safe, bodyless read path. A negative value is treated as zero.
func SetFetchRetries(n int) {
	if n < 0 {
		n = 0
	}
	FetchRetries = n
}

// SetHTTPTimeout configures the per-request timeout for the shared HTTP fetch
// path (page and script fetches, calibration probes, method probes, sitemaps).
// A non-positive value restores the default. Enterprise crawls of large bundles
// over slow links need this raised; interactive scans of flaky hosts may want it
// lowered so a single stalled request cannot hold up the whole crawl.
func SetHTTPTimeout(seconds int) {
	if seconds <= 0 {
		HTTPClientTimeout = 10 * time.Second
		return
	}
	HTTPClientTimeout = time.Duration(seconds) * time.Second
}

// Other limits
const (
	// MaxRedirects is the maximum number of HTTP redirects to follow
	MaxRedirects = 5

	// MaxParameterDisplayLength is the maximum length for parameter display in output
	MaxParameterDisplayLength = 100
)
