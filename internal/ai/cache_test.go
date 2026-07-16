package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// isolateCache points the per-user cache dir at a temp directory so tests never
// touch the real cache. os.UserCacheDir honours XDG_CACHE_HOME on Linux; on other
// platforms the test still runs but shares the temp root via HOME where possible.
func isolateCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
}

func TestPolicyCacheRoundTrip(t *testing.T) {
	isolateCache(t)
	fp := "deadbeef"
	rules := []Rule{{Pattern: `/api/`, Weight: 60, Reason: "api"}}
	if err := SaveCachedPolicy(fp, Compile(rules)); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := LoadCachedPolicy(fp)
	if !ok {
		t.Fatal("expected cache hit after save")
	}
	if got.Len() != 1 {
		t.Fatalf("loaded %d rules, want 1", got.Len())
	}
	if got.Bonus("https://x.test/api/users") != 60 {
		t.Errorf("loaded policy lost its weight")
	}
}

func TestPolicyCacheMissOnAbsent(t *testing.T) {
	isolateCache(t)
	if _, ok := LoadCachedPolicy("does-not-exist"); ok {
		t.Error("expected miss for absent fingerprint")
	}
}

func TestPolicyCacheRejectsVersionMismatch(t *testing.T) {
	isolateCache(t)
	fp := "versiontest"
	path, err := policyCachePath(fp)
	if err != nil {
		t.Fatal(err)
	}
	// Write a policy stamped with an incompatible version.
	data, _ := json.Marshal(wirePolicy{Version: policyVersion + 1, Rules: []Rule{{Pattern: "/x", Weight: 1}}})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadCachedPolicy(fp); ok {
		t.Error("expected miss for version mismatch")
	}
}

func TestPolicyCachePathUnderJSMinerDir(t *testing.T) {
	isolateCache(t)
	path, err := policyCachePath("abc")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(path)) != "policy" {
		t.Errorf("cache path %q not under a policy dir", path)
	}
}
