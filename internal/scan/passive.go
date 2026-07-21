package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// Passive URL discovery asks public web indexes for paths previously observed on
// the seed host. The returned URLs are hints only: the crawl rebases their paths
// onto the current seed origin and validates each response against status and
// catch-all fingerprints before the path is allowed to teach the permuter.
//
// Provider lookups deliberately use a separate request helper that never applies
// target headers. A target's Cookie or Authorization header must not be disclosed
// to a third-party archive.
const (
	passiveSourceWayback     = "wayback"
	passiveSourceCommonCrawl = "commoncrawl"
	defaultPassiveMax        = 100
	passiveProviderMaxBody   = 8 << 20
	passiveMaxRawURLLength   = 4096
	passiveMaxPathLength     = 2048
	passiveMaxPathSegments   = 64
)

var (
	waybackCDXEndpoint        = "https://web.archive.org/cdx/search/cdx"
	commonCrawlCollectionsURL = "https://index.commoncrawl.org/collinfo.json"
	defaultPassiveSourceNames = []string{passiveSourceWayback, passiveSourceCommonCrawl}
)

// passiveCandidate retains provenance so validated gathered-URL output and
// telemetry can explain where a historical path hint came from.
type passiveCandidate struct {
	URL        string
	Source     string
	ParamNames []string
}

// discoverPassiveURLs gathers, sanitizes, rebases, de-duplicates and ranks
// historical URL hints. Provider failures are intentionally best-effort: a
// public archive being unavailable must not abort an otherwise valid crawl.
func discoverPassiveURLs(seed *url.URL, sourceNames []string, max int) []passiveCandidate {
	if seed == nil || seed.Hostname() == "" {
		return nil
	}
	if max <= 0 {
		max = defaultPassiveMax
	}
	sourceNames = normalizePassiveSources(sourceNames)

	// Providers are independent and often have multi-second tail latency. Query
	// them in parallel, then fold their responses in the requested source order
	// so ranking, de-duplication and provenance remain deterministic.
	type providerResult struct {
		rawURLs []string
		err     error
	}
	results := make([]providerResult, len(sourceNames))
	var wg sync.WaitGroup
	for i, source := range sourceNames {
		i, source := i, source
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch source {
			case passiveSourceWayback:
				results[i].rawURLs, results[i].err = gatherWaybackURLs(seed.Hostname(), max)
			case passiveSourceCommonCrawl:
				results[i].rawURLs, results[i].err = gatherCommonCrawlURLs(seed.Hostname(), max)
			}
		}()
	}
	wg.Wait()

	seen := make(map[string]int)
	var candidates []passiveCandidate
	for i, source := range sourceNames {
		result := results[i]
		if result.err != nil {
			vlog(1, "[crawl] passive source %s unavailable: %v", source, result.err)
			continue
		}
		for _, raw := range result.rawURLs {
			live, params, ok := passivePathCandidateDetails(seed, raw)
			if !ok {
				continue
			}
			if idx, exists := seen[live]; exists {
				candidates[idx].ParamNames = uniqueSortedStrings(append(candidates[idx].ParamNames, params...))
				continue
			}
			seen[live] = len(candidates)
			candidates = append(candidates, passiveCandidate{URL: live, Source: source, ParamNames: params})
		}
	}

	// Spend a bounded crawl budget on the highest-yield historical hints first.
	// Provider order is not a useful ranking signal and archive indexes commonly
	// return old HTML pages before scripts, APIs and configuration resources.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if as, bs := targetScore(a.URL), targetScore(b.URL); as != bs {
			return as > bs
		}
		ap, bp := passivePathLength(a.URL), passivePathLength(b.URL)
		if ap != bp {
			return ap < bp
		}
		return a.URL < b.URL
	})
	if len(candidates) > max {
		candidates = candidates[:max]
	}
	return candidates
}

func normalizePassiveSources(in []string) []string {
	if len(in) == 0 {
		return append([]string(nil), defaultPassiveSourceNames...)
	}
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range in {
		for _, name := range strings.Split(raw, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			switch name {
			case passiveSourceWayback, passiveSourceCommonCrawl:
			default:
				if name != "" {
					vlog(1, "[crawl] ignoring unknown passive source %q", name)
				}
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// passivePathCandidate turns an archived absolute URL into a path-only hint on
// the live seed origin. It accepts only the exact seed hostname (not a subdomain)
// so paths from separate applications are never mixed, and intentionally drops
// the historical query and fragment: archived values frequently contain session
// tokens, PII and unbounded tracking variants.
func passivePathCandidate(seed *url.URL, raw string) (string, bool) {
	live, _, ok := passivePathCandidateDetails(seed, raw)
	return live, ok
}

// passivePathCandidateDetails preserves only historical query *names* as DOM
// source hints. Values and fragments are still discarded before any live target
// request, preventing archived tokens/PII from being replayed.
func passivePathCandidateDetails(seed *url.URL, raw string) (string, []string, bool) {
	raw = strings.TrimSpace(raw)
	if seed == nil || raw == "" || len(raw) > passiveMaxRawURLLength {
		return "", nil, false
	}
	archived, err := url.Parse(raw)
	if err != nil || archived.Opaque != "" ||
		(archived.Scheme != "http" && archived.Scheme != "https") ||
		archived.Hostname() == "" ||
		!strings.EqualFold(strings.TrimSuffix(archived.Hostname(), "."), strings.TrimSuffix(seed.Hostname(), ".")) {
		return "", nil, false
	}
	if archived.Path == "" || archived.Path == "/" ||
		len(archived.EscapedPath()) > passiveMaxPathLength ||
		strings.Contains(archived.Path, `\`) ||
		hasUnsafePathRune(archived.Path) {
		return "", nil, false
	}
	segments := strings.Split(strings.Trim(archived.Path, "/"), "/")
	if len(segments) > passiveMaxPathSegments {
		return "", nil, false
	}
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return "", nil, false
		}
	}
	paramNames := make([]string, 0, len(archived.Query()))
	for name := range archived.Query() {
		if validDOMSourceHintName(name) {
			paramNames = append(paramNames, name)
		}
	}
	sort.Strings(paramNames)

	live := *seed
	live.User = nil
	live.Path = archived.Path
	live.RawPath = archived.RawPath
	live.RawQuery = ""
	live.ForceQuery = false
	live.Fragment = ""
	if live.EscapedPath() == "" || len(live.String()) > passiveMaxRawURLLength ||
		!crawlableTarget(&live) {
		return "", nil, false
	}
	return normalizeCrawlURL(live.String()), paramNames, true
}

func hasUnsafePathRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func passivePathLength(raw string) int {
	if u, err := url.Parse(raw); err == nil {
		return len(u.EscapedPath())
	}
	return len(raw)
}

func gatherWaybackURLs(host string, limit int) ([]string, error) {
	endpoint, err := url.Parse(waybackCDXEndpoint)
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Add("filter", "statuscode:200")
	q.Set("collapse", "urlkey")
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("gzip", "false")
	endpoint.RawQuery = q.Encode()

	data, err := fetchPassiveProviderBody(endpoint.String())
	if err != nil {
		return nil, err
	}
	var rows [][]string
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("decode Wayback response: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	originalColumn := -1
	for i, name := range rows[0] {
		if name == "original" {
			originalColumn = i
			break
		}
	}
	if originalColumn < 0 {
		return nil, fmt.Errorf("Wayback response omitted original URL field")
	}
	out := make([]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if originalColumn < len(row) {
			out = append(out, row[originalColumn])
		}
	}
	return out, nil
}

type commonCrawlCollection struct {
	CDXAPI string `json:"cdx-api"`
}

func gatherCommonCrawlURLs(host string, limit int) ([]string, error) {
	data, err := fetchPassiveProviderBody(commonCrawlCollectionsURL)
	if err != nil {
		return nil, err
	}
	var collections []commonCrawlCollection
	if err := json.Unmarshal(data, &collections); err != nil {
		return nil, fmt.Errorf("decode Common Crawl collections: %w", err)
	}
	if len(collections) == 0 || collections[0].CDXAPI == "" {
		return nil, fmt.Errorf("Common Crawl returned no index collections")
	}

	collectionsEndpoint, err := url.Parse(commonCrawlCollectionsURL)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(collections[0].CDXAPI)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") ||
		!strings.EqualFold(endpoint.Scheme, collectionsEndpoint.Scheme) ||
		!strings.EqualFold(endpoint.Host, collectionsEndpoint.Host) {
		return nil, fmt.Errorf("Common Crawl advertised an unsafe index endpoint")
	}
	q := endpoint.Query()
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("fl", "url")
	q.Add("filter", "status:200")
	q.Set("collapse", "urlkey")
	q.Set("limit", fmt.Sprintf("%d", limit))
	endpoint.RawQuery = q.Encode()

	data, err = fetchPassiveProviderBody(endpoint.String())
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	var out []string
	for scanner.Scan() {
		var row struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			continue
		}
		if row.URL != "" {
			out = append(out, row.URL)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("decode Common Crawl response: %w", err)
	}
	return out, nil
}

// fetchPassiveProviderBody fetches a fixed public archive endpoint without
// applyHeaders. It sends only JSMiner's non-sensitive default User-Agent, keeps
// normal TLS certificate verification enabled even when the target scan uses
// -insecure, and confines redirects to the provider's exact origin.
func fetchPassiveProviderBody(raw string) ([]byte, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid passive provider URL %q", raw)
	}
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 10
	transport.MaxIdleConnsPerHost = 4
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: HTTPClientTimeout}
	providerHost := parsed.Hostname()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects ||
			!strings.EqualFold(req.URL.Scheme, parsed.Scheme) ||
			!strings.EqualFold(req.URL.Host, parsed.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	globalThrottle.waitHost(providerHost)
	resp, err := client.Do(req)
	globalThrottle.observeHost(providerHost, resp, err)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, passiveProviderMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > passiveProviderMaxBody {
		return nil, fmt.Errorf("provider response exceeded %d bytes", passiveProviderMaxBody)
	}
	return data, nil
}
