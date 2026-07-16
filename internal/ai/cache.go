package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Policy caching lets a rerun against the same site reuse a previously synthesised
// policy instead of paying for another model call, and makes repeated runs fully
// deterministic. A policy is stored as versioned JSON under the per-user cache
// directory, keyed by the digest fingerprint (which already folds in the model
// id), and written atomically (temp file + rename) so a crash mid-write can never
// leave a truncated, unreadable cache entry — the same approach the crawl
// checkpoint uses.

// policyCacheDir returns <user cache>/jsminer/policy, creating it if needed. It
// mirrors the browser cache layout the project already uses under the same root.
func policyCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "jsminer", "policy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func policyCachePath(fingerprint string) (string, error) {
	dir, err := policyCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fingerprint+".json"), nil
}

// LoadCachedPolicy returns the cached policy for fingerprint, and true, when a
// readable, version-matching entry exists. Any miss — absent, unreadable,
// malformed or wrong-version file — returns (nil, false) so the caller falls
// through to a fresh synthesis.
func LoadCachedPolicy(fingerprint string) (*Policy, bool) {
	path, err := policyCachePath(fingerprint)
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var wp wirePolicy
	if err := json.Unmarshal(data, &wp); err != nil {
		return nil, false
	}
	if wp.Version != policyVersion {
		return nil, false
	}
	return Compile(wp.Rules), true
}

// SaveCachedPolicy writes p to the cache under fingerprint. Errors are returned but
// are non-fatal to callers: a failed cache write only costs a future synthesis, it
// never affects the current crawl.
func SaveCachedPolicy(fingerprint string, p *Policy) error {
	path, err := policyCachePath(fingerprint)
	if err != nil {
		return err
	}
	wp := wirePolicy{Version: policyVersion, Rules: p.Rules()}
	data, err := json.Marshal(wp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jsminer-policy-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
