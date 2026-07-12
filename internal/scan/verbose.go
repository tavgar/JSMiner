package scan

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Verbosity controls how much diagnostic detail the scan package writes to the
// verbose log (stderr by default). It is 0 — silent — unless the caller raises
// it with SetVerbosity, and higher levels are cumulative:
//
//	1 (-v)   crawl narrative: matches found per page, in-scope targets
//	         discovered, queue growth, calibration and template-dedup skips.
//	2 (-vv)  network and render activity: every HTTP request with its method,
//	         status and size; every page render with the scripts and application
//	         states it surfaced.
//	3 (-vvv) per-item trace: individual target enqueue/skip decisions, method
//	         probes, parameter replays, permutations, followed imports and
//	         recovered source maps.
//
// Diagnostics go to stderr so they never contaminate the machine-readable
// results written to stdout.
var Verbosity int

var (
	verboseMu     sync.Mutex
	verboseWriter io.Writer = os.Stderr
)

// SetVerbosity sets the global verbose logging level (see Verbosity). Negative
// values are clamped to 0.
func SetVerbosity(level int) {
	if level < 0 {
		level = 0
	}
	Verbosity = level
}

// SetVerboseWriter redirects verbose diagnostics away from stderr, mainly so
// tests can capture them. Passing nil restores the default (os.Stderr).
func SetVerboseWriter(w io.Writer) {
	verboseMu.Lock()
	defer verboseMu.Unlock()
	if w == nil {
		w = os.Stderr
	}
	verboseWriter = w
}

// vEnabled reports whether a message at the given level would be emitted. Use it
// to guard log calls whose arguments are expensive to compute.
func vEnabled(level int) bool { return Verbosity >= level }

// vlog writes a single diagnostic line, prefixed with its level, when Verbosity
// is at least level. It is safe for concurrent use.
func vlog(level int, format string, args ...any) {
	if Verbosity < level {
		return
	}
	verboseMu.Lock()
	defer verboseMu.Unlock()
	fmt.Fprintf(verboseWriter, verbosePrefix(level)+format+"\n", args...)
}

// verbosePrefix tags each line with its level so interleaved output from
// different levels stays readable.
func verbosePrefix(level int) string {
	switch level {
	case 1:
		return "[v]   "
	case 2:
		return "[vv]  "
	default:
		return "[vvv] "
	}
}
