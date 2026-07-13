package scan

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// JSMiner renders pages in headless Chrome, but a scanned host may not have a
// browser installed — CI images, minimal containers and end-user machines often
// don't. Rather than fail the render (and silently lose all JavaScript-rendered
// and SPA-only discovery), JSMiner ships with a Chromium: it locates one bundled
// alongside its own executable and, failing that, provisions a pinned
// Chrome-for-Testing build into a managed cache the first time a render is needed.
// The result is remembered so subsequent renders reuse it.

var (
	// BrowserDownloadBaseURL is the Chrome-for-Testing storage base. It is a var so
	// tests can point provisioning at a local server instead of the internet.
	BrowserDownloadBaseURL = "https://storage.googleapis.com/chrome-for-testing-public"

	// BrowserVersionURL is the Chrome-for-Testing "last known good versions"
	// endpoint used to discover the latest stable version to download. A var so
	// tests can redirect it; an empty value skips the lookup and uses the fallback.
	BrowserVersionURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json"

	// PinnedChromeVersion is the Chrome-for-Testing build JSMiner falls back to when
	// the latest-version lookup is unavailable (e.g. offline). Normal operation
	// always resolves and downloads the current latest stable instead.
	PinnedChromeVersion = "131.0.6778.204"

	// AutoDownloadBrowser controls whether ResolveBrowser may download a browser
	// when none is found locally. It is on by default so rendering works out of the
	// box; -no-download-browser turns it off for air-gapped or bundle-only setups.
	AutoDownloadBrowser = true
)

// SetAutoDownloadBrowser toggles on-demand browser provisioning.
func SetAutoDownloadBrowser(on bool) { AutoDownloadBrowser = on }

var (
	resolvedBrowser     string
	resolveBrowserOnce  sync.Once
	provisionHTTPClient = func() *http.Client { return newHTTPClient() }
)

// resolvedBrowserPath returns the browser to launch, resolving (and provisioning)
// it once and caching the result for the process. An empty result means none was
// found and chromedp should fall back to its own PATH detection.
func resolvedBrowserPath() string {
	resolveBrowserOnce.Do(func() {
		resolvedBrowser = ResolveBrowser()
	})
	return resolvedBrowser
}

// resetResolvedBrowser clears the once-resolved browser so the next render
// re-resolves. It exists for tests that vary the provisioning configuration.
func resetResolvedBrowser() {
	resolveBrowserOnce = sync.Once{}
	resolvedBrowser = ""
}

// ResolveBrowser returns the path to a Chrome/Chromium executable to render with,
// provisioning one if necessary. An explicit -chrome-path / $JSMINER_CHROME
// override always wins. Otherwise, when downloads are enabled (the default), it
// always provisions the latest stable Chrome-for-Testing build — reusing that
// version if already cached, downloading it if not — so renders use an up-to-date
// browser. When downloads are disabled or fail (e.g. offline) it falls back to any
// previously cached build, a Chromium bundled next to the jsminer executable, or a
// browser on PATH. It returns "" only when every option is exhausted, leaving
// chromedp to try its own detection so behaviour is never worse than before.
func ResolveBrowser() string {
	if ChromePath != "" {
		return ChromePath
	}

	if AutoDownloadBrowser {
		version := chromeVersion()
		root := managedBrowserDir()
		if p := cachedBrowserForVersion(root, version); p != "" {
			vlog(1, "[browser] using cached latest Chromium %s at %s", version, p)
			return p
		}
		vlog(1, "[browser] downloading latest Chrome-for-Testing %s", version)
		if p, err := downloadBrowser(root, version); err == nil {
			vlog(1, "[browser] provisioned Chromium %s at %s", version, p)
			return p
		} else {
			vlog(1, "[browser] browser download failed: %v", err)
		}
	}

	// Fallbacks when download is disabled or failed.
	if p := anyCachedBrowser(); p != "" {
		vlog(1, "[browser] using cached Chromium at %s", p)
		return p
	}
	if p := bundledBrowserPath(); p != "" {
		vlog(1, "[browser] using bundled Chromium at %s", p)
		return p
	}
	if p := pathBrowserPath(); p != "" {
		vlog(2, "[browser] using Chrome/Chromium on PATH at %s", p)
		return p
	}
	return ""
}

// chromeVersion resolves the browser version to provision: the current latest
// stable Chrome-for-Testing release, or the pinned fallback when that lookup is
// unavailable.
func chromeVersion() string {
	if v := latestChromeVersion(); v != "" {
		return v
	}
	return PinnedChromeVersion
}

// latestChromeVersion queries the Chrome-for-Testing "last known good versions"
// endpoint and returns the Stable channel version, or "" on any failure so the
// caller can fall back.
func latestChromeVersion() string {
	if BrowserVersionURL == "" {
		return ""
	}
	req, err := http.NewRequest("GET", BrowserVersionURL, nil)
	if err != nil {
		return ""
	}
	applyHeaders(req)
	client := provisionHTTPClient()
	client.Timeout = 15 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		vlog(2, "[browser] latest-version lookup failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	var parsed struct {
		Channels struct {
			Stable struct {
				Version string `json:"version"`
			} `json:"Stable"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Channels.Stable.Version)
}

// cftPlatform returns the Chrome-for-Testing platform token for the current OS and
// architecture, plus the executable's path within the extracted archive. ok is
// false on an unsupported platform.
func cftPlatform() (platform, exeSubpath string, ok bool) {
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH != "amd64" {
			return "", "", false
		}
		return "linux64", filepath.Join("chrome-linux64", "chrome"), true
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "mac-arm64", filepath.Join("chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"), true
		}
		return "mac-x64", filepath.Join("chrome-mac-x64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"), true
	case "windows":
		return "win64", filepath.Join("chrome-win64", "chrome.exe"), true
	default:
		return "", "", false
	}
}

// browserDownloadURL builds the Chrome-for-Testing zip URL for a version and the
// current platform.
func browserDownloadURL(base, version, platform string) string {
	return fmt.Sprintf("%s/%s/%s/chrome-%s.zip", strings.TrimSuffix(base, "/"), version, platform, platform)
}

// managedBrowserDir is the root under which JSMiner caches provisioned browsers,
// per user, falling back to the temp dir when no user cache dir is available.
func managedBrowserDir() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "jsminer", "browser")
	}
	return filepath.Join(os.TempDir(), "jsminer", "browser")
}

// executableDir returns the directory holding the running jsminer binary, or ""
// when it cannot be determined.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// bundledBrowserPath looks for a Chromium shipped alongside the jsminer
// executable — the layout a release archive that bundles a browser would use —
// and returns the executable path if one is present and runnable.
func bundledBrowserPath() string {
	dir := executableDir()
	if dir == "" {
		return ""
	}
	_, exeSub, ok := cftPlatform()
	if !ok {
		return ""
	}
	candidates := []string{
		filepath.Join(dir, "chromium", exeSub),        // bundled CfT archive layout
		filepath.Join(dir, "chromium", chromeLeaf()),  // flattened: chromium/chrome
		filepath.Join(dir, "chrome-headless-shell", chromeLeaf()),
	}
	for _, c := range candidates {
		if isExecutableFile(c) {
			return c
		}
	}
	return ""
}

// cachedBrowserForVersion returns the provisioned browser in the managed cache
// for a specific version, if present and runnable.
func cachedBrowserForVersion(root, version string) string {
	_, exeSub, ok := cftPlatform()
	if !ok {
		return ""
	}
	p := filepath.Join(root, version, exeSub)
	if isExecutableFile(p) {
		return p
	}
	return ""
}

// anyCachedBrowser returns any previously provisioned browser in the managed
// cache, regardless of version, so an offline run can still render with a build
// downloaded earlier.
func anyCachedBrowser() string {
	_, exeSub, ok := cftPlatform()
	if !ok {
		return ""
	}
	root := managedBrowserDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(root, e.Name(), exeSub)
		if isExecutableFile(p) {
			return p
		}
	}
	return ""
}

// pathBrowserPath returns a Chrome/Chromium already discoverable on PATH, matching
// the binary names chromedp itself looks for.
func pathBrowserPath() string {
	for _, name := range []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		"chrome", "chrome-headless-shell", "headless_shell",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// chromeLeaf is the bare browser executable name for the current OS.
func chromeLeaf() string {
	if runtime.GOOS == "windows" {
		return "chrome.exe"
	}
	return "chrome"
}

// isExecutableFile reports whether path is an existing regular file (with the
// executable bit set on non-Windows systems).
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode()&0o111 != 0
}

// downloadBrowser fetches the Chrome-for-Testing zip for version into destRoot,
// extracts it under destRoot/<version>/ and returns the browser executable path.
// This is the managed-cache layout resolvedBrowserPath reads.
func downloadBrowser(destRoot, version string) (string, error) {
	_, exeSub, ok := cftPlatform()
	if !ok {
		return "", fmt.Errorf("unsupported platform %s/%s for browser download", runtime.GOOS, runtime.GOARCH)
	}
	versionDir := filepath.Join(destRoot, version)
	return fetchAndExtractBrowser(version, versionDir, filepath.Join(versionDir, exeSub))
}

// ProvisionBundle downloads the pinned Chromium and extracts it into dir/chromium,
// the layout bundledBrowserPath detects, so dir (holding the jsminer binary and
// this chromium/ directory) can be shipped as one self-contained archive that
// renders without any separate browser install or runtime download.
func ProvisionBundle(dir string) (string, error) {
	_, exeSub, ok := cftPlatform()
	if !ok {
		return "", fmt.Errorf("unsupported platform %s/%s for browser download", runtime.GOOS, runtime.GOARCH)
	}
	chromiumDir := filepath.Join(dir, "chromium")
	return fetchAndExtractBrowser(chromeVersion(), chromiumDir, filepath.Join(chromiumDir, exeSub))
}

// fetchAndExtractBrowser downloads the pinned/known browser archive for the given
// version and extracts it into extractDir, returning exePath. It is idempotent: a
// runnable browser already present at exePath is reused without re-downloading.
func fetchAndExtractBrowser(version, extractDir, exePath string) (string, error) {
	platform, _, ok := cftPlatform()
	if !ok {
		return "", fmt.Errorf("unsupported platform %s/%s for browser download", runtime.GOOS, runtime.GOARCH)
	}
	if isExecutableFile(exePath) {
		return exePath, nil
	}
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", err
	}

	url := browserDownloadURL(BrowserDownloadBaseURL, version, platform)
	tmp, err := os.CreateTemp(extractDir, "chrome-*.zip")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := fetchToFile(url, tmp); err != nil {
		tmp.Close()
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	if err := unzipInto(tmpName, extractDir); err != nil {
		return "", fmt.Errorf("extract browser archive: %w", err)
	}
	if !isExecutableFile(exePath) && runtime.GOOS != "windows" {
		_ = os.Chmod(exePath, 0o755)
	}
	if !isExecutableFile(exePath) {
		return "", fmt.Errorf("browser executable not found after extraction at %s", exePath)
	}
	return exePath, nil
}

// fetchToFile downloads url into w through the shared (throttled, header-applying)
// HTTP path, streaming the body so a large archive does not buffer in memory.
func fetchToFile(url string, w io.Writer) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	applyHeaders(req)
	client := provisionHTTPClient()
	// A browser archive is ~150MB; give it far longer than a normal request.
	client.Timeout = 10 * time.Minute
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// unzipInto extracts the zip at src into dir, preserving the archive's internal
// paths and the executable bits of its entries. It guards against Zip-Slip by
// rejecting any entry whose resolved path escapes dir.
func unzipInto(src, dir string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()

	root := filepath.Clean(dir) + string(os.PathSeparator)
	for _, f := range zr.File {
		target := filepath.Join(dir, f.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), root) &&
			filepath.Clean(target) != filepath.Clean(dir) {
			return fmt.Errorf("zip entry escapes destination: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractZipFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

// extractZipFile writes a single zip entry to target, applying its stored mode so
// the browser and its helpers stay executable.
func extractZipFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	mode := f.Mode()
	if mode == 0 {
		mode = 0o644
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
