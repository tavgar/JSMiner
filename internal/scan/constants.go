package scan

import "time"

// Network and buffer sizes
const (
	// MaxPostDataSize is the maximum POST data size that Chrome DevTools will capture
	MaxPostDataSize = 64 * 1024 // 64KB

	// InitialBufferSize is the initial size for scanner buffers
	InitialBufferSize = 1024 // 1KB

	// MaxBufferSize is the maximum size for scanner buffers
	MaxBufferSize = 1024 * 1024 // 1MB
)

// Timeouts and delays
var (
	// RenderTimeout is the timeout for page rendering operations
	RenderTimeout = 15 * time.Second

	// RenderSleepDuration is the wait time for dynamic content to load
	RenderSleepDuration = 8 * time.Second

	// HTTPClientTimeout is the timeout for HTTP requests
	HTTPClientTimeout = 10 * time.Second
)

// SetRenderSleepDuration allows customizing the sleep duration for page rendering
func SetRenderSleepDuration(seconds int) {
	RenderSleepDuration = time.Duration(seconds) * time.Second
}

// Other limits
const (
	// MaxRedirects is the maximum number of HTTP redirects to follow
	MaxRedirects = 5

	// MaxParameterDisplayLength is the maximum length for parameter display in output
	MaxParameterDisplayLength = 100
)