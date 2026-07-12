package scan

import (
	"bytes"
	"strings"
	"testing"
)

// withVerbosity sets the verbosity level and capture buffer for the duration of
// a test, restoring the defaults afterwards.
func withVerbosity(t *testing.T, level int) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	SetVerbosity(level)
	SetVerboseWriter(&buf)
	t.Cleanup(func() {
		SetVerbosity(0)
		SetVerboseWriter(nil)
	})
	return &buf
}

func TestVlogRespectsLevel(t *testing.T) {
	buf := withVerbosity(t, 1)

	vlog(1, "shown at %d", 1)
	vlog(2, "hidden at %d", 2)

	got := buf.String()
	if !strings.Contains(got, "shown at 1") {
		t.Errorf("level-1 message should be logged when Verbosity=1, got %q", got)
	}
	if strings.Contains(got, "hidden at 2") {
		t.Errorf("level-2 message should be suppressed when Verbosity=1, got %q", got)
	}
	if !strings.HasPrefix(got, "[v]   ") {
		t.Errorf("level-1 line should carry the [v] prefix, got %q", got)
	}
}

func TestVlogCumulative(t *testing.T) {
	buf := withVerbosity(t, 3)

	vlog(1, "one")
	vlog(2, "two")
	vlog(3, "three")

	got := buf.String()
	for _, want := range []string{"[v]   one", "[vv]  two", "[vvv] three"} {
		if !strings.Contains(got, want) {
			t.Errorf("Verbosity=3 should include %q, got %q", want, got)
		}
	}
}

func TestVlogSilentByDefault(t *testing.T) {
	buf := withVerbosity(t, 0)

	vlog(1, "should not appear")

	if buf.Len() != 0 {
		t.Errorf("no output expected at Verbosity=0, got %q", buf.String())
	}
	if vEnabled(1) {
		t.Error("vEnabled(1) should be false at Verbosity=0")
	}
}

func TestSetVerbosityClampsNegative(t *testing.T) {
	SetVerbosity(-5)
	t.Cleanup(func() { SetVerbosity(0) })
	if Verbosity != 0 {
		t.Errorf("negative verbosity should clamp to 0, got %d", Verbosity)
	}
}
