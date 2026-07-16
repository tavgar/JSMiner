package scan

import (
	"strings"
	"testing"
	"time"
)

// TestParseRobotsCrawlDelay checks that a Crawl-delay under the catch-all group is
// read (as a per-request gap) while one under a named-bot group is ignored.
func TestParseRobotsCrawlDelay(t *testing.T) {
	body := strings.Join([]string{
		"User-agent: Googlebot",
		"Crawl-delay: 20", // named bot: must be ignored
		"",
		"User-agent: *",
		"Disallow: /admin/",
		"Crawl-delay: 2.5", // catch-all: honoured
	}, "\n")
	_, _, delay := parseRobots(body, "https://example.test")
	if want := 2500 * time.Millisecond; delay != want {
		t.Fatalf("crawl delay = %v, want %v", delay, want)
	}
}

// TestParseRobotsCrawlDelayClamped verifies an absurd Crawl-delay is clamped so it
// cannot freeze a scan.
func TestParseRobotsCrawlDelayClamped(t *testing.T) {
	body := "User-agent: *\nCrawl-delay: 100000"
	_, _, delay := parseRobots(body, "https://example.test")
	if delay != maxRobotsCrawlDelay {
		t.Fatalf("crawl delay = %v, want clamp to %v", delay, maxRobotsCrawlDelay)
	}
}

// TestParseRobotsNoCrawlDelay verifies zero is returned when no Crawl-delay is
// present, and that a bare Crawl-delay preceding any User-agent line (sloppy but
// common) is still honoured for the catch-all.
func TestParseRobotsNoCrawlDelay(t *testing.T) {
	if _, _, d := parseRobots("Disallow: /x\nSitemap: https://e.test/s.xml", "https://e.test"); d != 0 {
		t.Fatalf("crawl delay = %v, want 0 when absent", d)
	}
	if _, _, d := parseRobots("Crawl-delay: 3", "https://e.test"); d != 3*time.Second {
		t.Fatalf("leading crawl delay = %v, want 3s", d)
	}
}

// TestSetHostRateFloor verifies the throttle applies a per-host floor and that
// adaptive decay never eases the gap below it.
func TestSetHostRateFloor(t *testing.T) {
	ResetThrottle()
	defer ResetThrottle()

	const host = "floor.example"
	SetHostRateFloor(host, 750*time.Millisecond)

	globalThrottle.mu.Lock()
	hs := globalThrottle.host(host)
	got := hs.curGap
	base := globalThrottle.baseGapFor(host)
	globalThrottle.mu.Unlock()

	if got < 750*time.Millisecond {
		t.Fatalf("host gap = %v, want >= 750ms floor", got)
	}
	if base != 750*time.Millisecond {
		t.Fatalf("effective base gap = %v, want the 750ms floor", base)
	}

	// Drive many clean responses; decay must not drop below the floor.
	for i := 0; i < 50; i++ {
		globalThrottle.decay(host)
	}
	globalThrottle.mu.Lock()
	after := globalThrottle.host(host).curGap
	globalThrottle.mu.Unlock()
	if after < 750*time.Millisecond {
		t.Fatalf("gap decayed to %v, below the 750ms floor", after)
	}
}

// TestSetHostRateFloorKeepsStricterUserLimit verifies a larger user base gap is
// not lowered by a smaller robots.txt floor.
func TestSetHostRateFloorKeepsStricterUserLimit(t *testing.T) {
	ResetThrottle()
	defer func() { SetRateLimit(0); ResetThrottle() }()

	SetRateLimit(1) // 1 req/s => 1s base gap for every host
	SetHostRateFloor("h.example", 200*time.Millisecond)

	globalThrottle.mu.Lock()
	base := globalThrottle.baseGapFor("h.example")
	globalThrottle.mu.Unlock()
	if base != time.Second {
		t.Fatalf("effective base gap = %v, want the stricter 1s user limit", base)
	}
}
