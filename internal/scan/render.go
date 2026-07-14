package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// HTTPRequest represents a captured HTTP request.
type HTTPRequest struct {
	URL  string
	Body string
}

// newRenderContext creates the headless-Chrome context shared by every render
// helper, with an error logger that drops two classes of benign chromedp noise:
//
//   - "unhandled node event" lines. chromedp mirrors the page DOM from CDP
//     mutation events and logs an error for any event type it has no case for —
//     notably dom.EventTopLayerElementsUpdated, fired whenever a <dialog>,
//     popover or fullscreen element enters or leaves the top layer. Those events
//     carry no payload and do not affect the rendered HTML we scan.
//
//   - "unknown IPAddressSpace value" unmarshal failures. Newer Chrome reports
//     CDP IPAddressSpace enum values (e.g. "Loopback", added when the Private
//     Network Access spec split it out of "Local") that our pinned cdproto
//     bindings don't recognise, so the requestWillBeSentExtraInfo /
//     responseReceivedExtraInfo events fail to unmarshal. These are ancillary
//     security-metadata events; the response bodies and navigation we scan are
//     unaffected, and the noise appears whenever a loopback/localhost target is
//     scanned.
//
// Every other error is reported exactly as chromedp's default logger would.
func newRenderContext(parent context.Context) (context.Context, context.CancelFunc) {
	return chromedp.NewContext(parent, chromedp.WithErrorf(func(format string, args ...any) {
		if strings.Contains(format, "unhandled node event") {
			return
		}
		if strings.Contains(fmt.Sprintf(format, args...), "unknown IPAddressSpace value") {
			return
		}
		log.Printf("ERROR: "+format, args...)
	}))
}

// ChromePath, when set, is the explicit path to the Chrome/Chromium executable
// used for rendering. It is empty by default, in which case chromedp auto-detects
// a browser on PATH. Setting it lets JSMiner render in environments where Chrome
// is installed at a known location that is not on PATH — common in CI images and
// containers (Playwright/Puppeteer browser caches, custom installs) — where
// auto-detection would otherwise fail and rendering would silently fall back to a
// static fetch.
var ChromePath string

// SetChromePath configures an explicit Chrome/Chromium executable path for
// rendering. An empty value restores chromedp's PATH-based auto-detection.
func SetChromePath(path string) { ChromePath = path }

// renderExecOptions builds the headless-Chrome allocator options shared by every
// render helper.
func renderExecOptions() []chromedp.ExecAllocatorOption {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	// Resolve (and, if needed, provision) a browser: an explicit override, one
	// bundled with jsminer, a cached download, or a fresh Chrome-for-Testing build.
	// An empty result leaves chromedp to auto-detect on PATH as before.
	if browser := resolvedBrowserPath(); browser != "" {
		opts = append(opts, chromedp.ExecPath(browser))
	}
	if SkipTLSVerification {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	return opts
}

// renderHeaders returns the request headers to apply during rendering: the
// default (or user-overridden) User-Agent plus any extra headers, matching the
// headers used by the plain HTTP fetch path.
func renderHeaders() map[string]interface{} {
	headers := map[string]interface{}{"User-Agent": defaultUserAgent}
	if vals := extraHeaders.Values("User-Agent"); len(vals) > 0 {
		headers["User-Agent"] = vals[len(vals)-1]
	}
	for k, vals := range extraHeaders {
		if strings.EqualFold(k, "User-Agent") || len(vals) == 0 {
			continue
		}
		headers[k] = vals[len(vals)-1]
	}
	return headers
}

// headerActions returns the chromedp actions that install the given headers and
// matching User-Agent override, or nil when there are none.
func headerActions(headers map[string]interface{}) []chromedp.Action {
	if len(headers) == 0 {
		return nil
	}
	return []chromedp.Action{
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		emulation.SetUserAgentOverride(headers["User-Agent"].(string)),
	}
}

// retryAfterFromHeaders extracts the Retry-After header value from a CDP response
// header map, matching case-insensitively. It returns "" when absent.
func retryAfterFromHeaders(h network.Headers) string {
	for k, v := range h {
		if strings.EqualFold(k, "Retry-After") {
			if s, ok := v.(string); ok {
				return s
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// noteRenderResponse feeds a response headless Chrome received into the shared
// throttle when it is a rate-limit/overload signal, so a 429/503 the browser hits
// during a render backs off the whole scan even though Chrome's own fetches never
// pass through the Go request path. respURL is the URL of the response, so the
// backoff is applied against the host that actually rate-limited rather than
// globally.
func noteRenderResponse(respURL string, status int, h network.Headers) {
	if isThrottleStatus(status) {
		globalThrottle.noteThrottledHost(hostOf(respURL), status, retryAfterFromHeaders(h))
	}
}

// RenderURL loads the page at urlStr in headless Chrome and returns the
// rendered HTML along with JavaScript URLs fetched during the page load.
func RenderURL(urlStr string) ([]byte, []string, error) {
	// Pace the render against the shared throttle before arming the timeout, so a
	// backoff sleep cannot consume the render budget (see renderStates).
	globalThrottle.waitHost(hostOf(urlStr))

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), renderExecOptions()...)
	defer cancel()

	ctx, cancelCtx := newRenderContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, RenderTimeout)
	defer cancelTimeout()

	headers := renderHeaders()

	scriptSet := make(map[string]struct{})
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if e, ok := ev.(*network.EventResponseReceived); ok {
			noteRenderResponse(e.Response.URL, int(e.Response.Status), e.Response.Headers)
			u := e.Response.URL
			if strings.HasSuffix(strings.ToLower(u), ".js") ||
				strings.Contains(e.Response.MimeType, "javascript") {
				scriptSet[u] = struct{}{}
			}
		}
	})

	var html string
	actions := []chromedp.Action{network.Enable()}
	actions = append(actions, headerActions(headers)...)
	actions = append(actions,
		chromedp.Navigate(urlStr),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(RenderSleepDuration),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	vlog(2, "render %s (plain)", urlStr)
	err := chromedp.Run(ctx, actions...)
	if err != nil {
		vlog(2, "render %s -> error: %v", urlStr, err)
		return nil, nil, err
	}

	scripts := scriptKeys(scriptSet)
	vlog(2, "render %s -> %d byte(s), %d script(s)", urlStr, len(html), len(scripts))
	return []byte(html), scripts, nil
}

// RenderURLWithRequests loads the page and captures POST requests made during
// rendering. It returns the rendered HTML, JavaScript URLs and POST requests.
func RenderURLWithRequests(urlStr string) ([]byte, []string, []HTTPRequest, error) {
	states, scripts, posts, _, err := renderStates(urlStr, false)
	if err != nil {
		return nil, nil, nil, err
	}
	var html []byte
	if len(states) > 0 {
		html = states[0]
	}
	return html, scripts, posts, nil
}

// RenderURLWithStates loads the page and then explores application state that
// only appears after interaction: it clicks client-side navigation controls and
// fills forms with plausible valid values and submits them, snapshotting each
// distinct DOM state it reaches. It returns those state snapshots (the initial
// load first), the union of JavaScript URLs seen across all states, the POST
// requests captured throughout, and the URLs of the XHR/fetch API calls the page
// made — so a single-page app whose surface lives behind event handlers is
// scanned in every state, not just the shell it first renders, and the API
// endpoints its dynamic navigation calls are discovered even when no bundle
// mentions them literally.
//
// Interaction is bounded by MaxExploreStates; when that is zero the result is a
// single state and this behaves like RenderURLWithRequests.
func RenderURLWithStates(urlStr string) ([][]byte, []string, []HTTPRequest, []string, error) {
	return renderStates(urlStr, MaxExploreStates > 0)
}

// renderStates performs the initial render and, when explore is set, drives
// interaction-based exploration of further states. It is the shared engine
// behind RenderURLWithRequests (explore off) and RenderURLWithStates.
func renderStates(urlStr string, explore bool) ([][]byte, []string, []HTTPRequest, []string, error) {
	// Respect the shared throttle's proactive spacing and any active backoff
	// before starting a render. This must happen before the render timeout is
	// armed below, otherwise a backoff sleep would eat into the render budget and
	// could expire the context before Chrome even navigates.
	globalThrottle.waitHost(hostOf(urlStr))

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), renderExecOptions()...)
	defer cancel()

	ctx, cancelCtx := newRenderContext(allocCtx)
	defer cancelCtx()

	timeout := RenderTimeout
	if explore {
		timeout += exploreBudget()
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	headers := renderHeaders()

	scriptSet := make(map[string]struct{})
	xhrSet := make(map[string]struct{})
	reqMap := make(map[network.RequestID]*HTTPRequest)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			noteRenderResponse(e.Response.URL, int(e.Response.Status), e.Response.Headers)
			u := e.Response.URL
			if strings.HasSuffix(strings.ToLower(u), ".js") ||
				strings.Contains(e.Response.MimeType, "javascript") {
				scriptSet[u] = struct{}{}
			}
		case *network.EventRequestWillBeSent:
			if e.Request == nil {
				break
			}
			// Record the URLs of XHR/fetch API calls the page makes. Single-page
			// apps routinely build these paths at runtime — from an id fetched from
			// another endpoint, a template literal, a router param — so they never
			// appear as a literal string in any shipped bundle and are invisible to
			// static scanning: the live request is the only place they surface.
			// Capturing them lets the crawler reach the endpoints, and the secrets
			// in their responses, that dynamic navigation reveals. Body-bearing
			// verbs are already recorded as posts below, so only the remaining
			// methods are added here to avoid reporting one URL as both an endpoint
			// and a post.
			if e.Type == network.ResourceTypeXHR || e.Type == network.ResourceTypeFetch {
				switch e.Request.Method {
				case "POST", "PUT", "PATCH":
				default:
					if strings.HasPrefix(e.Request.URL, "http://") || strings.HasPrefix(e.Request.URL, "https://") {
						xhrSet[e.Request.URL] = struct{}{}
					}
				}
			}
			// The CDP network listener captures request-bearing verbs even across
			// the navigations a form submit or client-side route change triggers, so
			// it is the reliable record of what the interactions fired.
			if e.Request.Method == "POST" || e.Request.Method == "PUT" || e.Request.Method == "PATCH" {
				reqMap[e.RequestID] = &HTTPRequest{URL: e.Request.URL}
			}
		}
	})

	var baseHTML string
	actions := []chromedp.Action{network.Enable().WithMaxPostDataSize(MaxPostDataSize)}
	actions = append(actions, headerActions(headers)...)
	actions = append(actions,
		chromedp.Navigate(urlStr),
		chromedp.Evaluate(interactionScript, nil),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(RenderSleepDuration),
		chromedp.OuterHTML("html", &baseHTML, chromedp.ByQuery),
	)
	vlog(2, "render %s (explore=%t)", urlStr, explore)
	if err := chromedp.Run(ctx, actions...); err != nil {
		vlog(2, "render %s -> error: %v", urlStr, err)
		return nil, nil, nil, nil, err
	}

	states := [][]byte{[]byte(baseHTML)}
	seen := map[string]struct{}{structuralSig([]byte(baseHTML)): {}}
	winPosts := readWindowPosts(ctx, nil)

	if explore {
		before := len(states)
		states, winPosts = exploreStates(ctx, states, seen, winPosts)
		vlog(2, "render %s -> explored %d additional state(s)", urlStr, len(states)-before)
	}

	scripts := scriptKeys(scriptSet)
	xhrURLs := scriptKeys(xhrSet)
	posts := mergePosts(ctx, reqMap, winPosts)
	vlog(2, "render %s -> %d state(s), %d script(s), %d xhr(s), %d post(s)", urlStr, len(states), len(scripts), len(xhrURLs), len(posts))
	return states, scripts, posts, xhrURLs, nil
}

// exploreStates drives interaction-based state discovery against an already
// loaded page. It fills and submits each form with plausible valid values, then
// clicks each client-side navigation candidate, snapshotting every structurally
// new DOM state it reaches and recording the request-bearing calls those
// interactions fire.
//
// Exploration is sequential — each interaction builds on the state the previous
// one left, so an app that reveals its surface progressively (tabs, wizards,
// route changes) is followed inward rather than always from the shell. It does
// not try to reset to the base between steps: in a headless context the history
// begins at about:blank, so a naive back() would strand exploration there.
// Candidates are re-tagged before every attempt, so indices stay valid after the
// DOM is rebuilt by a route change or a submit navigates to a new page. It is
// best-effort and defensive — a failed step is skipped, not fatal — and bounded
// by MaxExploreStates and exploreMaxAttempts so a busy page cannot run away.
func exploreStates(ctx context.Context, states [][]byte, seen map[string]struct{}, winPosts []HTTPRequest) ([][]byte, []HTTPRequest) {
	maxAttempts := exploreMaxAttempts()

	record := func(html string) {
		winPosts = readWindowPosts(ctx, winPosts)
		sig := structuralSig([]byte(html))
		if _, ok := seen[sig]; ok {
			return
		}
		seen[sig] = struct{}{}
		states = append(states, []byte(html))
	}

	// submitForms fills and submits every form in the DOM currently loaded,
	// recording each resulting state. It reveals what lives behind a submission
	// handler (search results, filtered views, wizard steps, tokens minted on
	// login) and captures the endpoint it posts to. Because it runs against
	// whatever state is loaded now, it is invoked both from the pristine base and
	// after each client-side navigation — a form reached only by navigating to a
	// route (e.g. /login) is otherwise never exercised.
	submitForms := func() {
		for idx := 0; len(states) <= MaxExploreStates && idx < maxAttempts; idx++ {
			var forms []exploreForm
			if err := chromedp.Run(ctx,
				chromedp.Evaluate(interactionScript, nil),
				chromedp.Evaluate("window.__jsm.tagForms()", &forms),
			); err != nil {
				return
			}
			if idx >= len(forms) {
				return
			}
			valsJSON, err := json.Marshal(formValues(forms[idx]))
			if err != nil {
				continue
			}
			var submitted bool
			var html string
			if err := chromedp.Run(ctx,
				chromedp.Evaluate(fmt.Sprintf("window.__jsm.fillAndSubmit(%d, %s)", idx, string(valsJSON)), &submitted),
				chromedp.Sleep(ExploreSettleDuration),
				chromedp.OuterHTML("html", &html, chromedp.ByQuery),
			); err != nil {
				continue
			}
			if submitted {
				record(html)
			}
		}
	}

	// Forms first, from the pristine base state.
	submitForms()

	// Client-side navigation: buttons and in-page/JS links that reveal state
	// through event handlers rather than a fresh URL (real URL navigations are
	// already covered by the crawl's link graph).
	for idx := 0; len(states) <= MaxExploreStates && idx < maxAttempts; idx++ {
		var n int
		if err := chromedp.Run(ctx,
			chromedp.Evaluate(interactionScript, nil),
			chromedp.Evaluate("window.__jsm.tagClickables()", &n),
		); err != nil {
			break
		}
		if idx >= n {
			break
		}
		var clicked bool
		var html string
		if err := chromedp.Run(ctx,
			chromedp.Evaluate(fmt.Sprintf("window.__jsm.click(%d)", idx), &clicked),
			chromedp.Sleep(ExploreSettleDuration),
			chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		); err != nil {
			continue
		}
		if clicked {
			record(html)
			// A click may reveal a form (a modal, a revealed panel); submit it.
			submitForms()
		}
	}

	// Client-side route links: same-origin <a href> routes an SPA renders in
	// place. When every route serves an identical shell the crawl dedups them
	// before rendering, so driving them here is the only way each route's
	// client-rendered DOM — and any secret injected once it mounts — is scanned.
	//
	// This is gated to genuine single-page apps: a window-persistent token is set
	// once, and if a click triggers a real document navigation (a classic
	// multi-page site, whose links the crawl already follows) the token is gone
	// and the pass stops immediately, so multi-page crawls are not slowed by
	// re-rendering pages the crawl fetches anyway.
	const routeToken = "__jsm_route_token__"
	if err := chromedp.Run(ctx, chromedp.Evaluate(interactionScript+"\nwindow.__jsmRouteToken="+strconv.Quote(routeToken)+";", nil)); err == nil {
		visitedRoutes := map[string]struct{}{}
		if p := currentRoutePath(ctx); p != "" {
			visitedRoutes[p] = struct{}{}
		}
		for i := 0; len(states) <= MaxExploreStates && i < maxAttempts; i++ {
			var paths []string
			if err := chromedp.Run(ctx, chromedp.Evaluate("(window.__jsm&&window.__jsm.tagRouteLinks)?window.__jsm.tagRouteLinks():[]", &paths)); err != nil {
				break
			}
			idx := -1
			for j, p := range paths {
				if _, ok := visitedRoutes[p]; !ok {
					visitedRoutes[p] = struct{}{}
					idx = j
					break
				}
			}
			if idx < 0 {
				break // no unvisited same-origin routes remain
			}
			var clicked bool
			var html string
			if err := chromedp.Run(ctx,
				chromedp.Evaluate(fmt.Sprintf("(window.__jsm&&window.__jsm.clickRoute)?window.__jsm.clickRoute(%d):false", idx), &clicked),
				chromedp.Sleep(ExploreSettleDuration),
				chromedp.OuterHTML("html", &html, chromedp.ByQuery),
			); err != nil {
				continue
			}
			var token string
			if err := chromedp.Run(ctx, chromedp.Evaluate("window.__jsmRouteToken||''", &token)); err != nil {
				break
			}
			vlog(3, "[route] drove client-side route %q (clicked=%t, spa=%t)", paths[idx], clicked, token == routeToken)
			if token != routeToken {
				// A real document navigation occurred: this is not an in-place SPA
				// route, and the crawl already follows such links. Stop here.
				break
			}
			if clicked {
				record(html)
				// Exercise any form this route renders (e.g. a /login form), which
				// the base-state forms pass could not reach.
				submitForms()
			}
		}
	}

	return states, winPosts
}

// currentRoutePath returns the browser's current path+query, used to avoid
// re-driving the route the exploration already sits on.
func currentRoutePath(ctx context.Context) string {
	var p string
	if err := chromedp.Run(ctx, chromedp.Evaluate("location.pathname + location.search", &p)); err != nil {
		return ""
	}
	return p
}

// exploreMaxAttempts bounds how many interactions each exploration pass (forms,
// then clicks) attempts, keeping the exploration time-bounded on pages with many
// controls even when few of them yield a new state.
func exploreMaxAttempts() int {
	return MaxExploreStates * 3
}

// exploreBudget is the extra time granted to the render context to perform
// interactions, sized from the two passes' attempt caps and the per-interaction
// settle time.
func exploreBudget() time.Duration {
	return time.Duration(2*exploreMaxAttempts()) * ExploreSettleDuration
}

// readWindowPosts reads the POST/PUT/PATCH requests the injected hooks recorded
// on window.__interceptedPOSTs and merges them into acc, deduplicating on
// URL+body. It is called after each interaction so bodies are captured before a
// subsequent navigation can clear the page's array.
func readWindowPosts(ctx context.Context, acc []HTTPRequest) []HTTPRequest {
	var got []HTTPRequest
	if err := chromedp.Run(ctx, chromedp.Evaluate("window.__interceptedPOSTs || []", &got)); err != nil {
		return acc
	}
	for _, p := range got {
		dup := false
		for _, e := range acc {
			if e.URL == p.URL && e.Body == p.Body {
				dup = true
				break
			}
		}
		if !dup {
			acc = append(acc, p)
		}
	}
	return acc
}

// mergePosts combines the CDP-captured requests (which survive navigations but
// may lack a body) with the hook-captured window posts (which carry bodies),
// filling in missing bodies and dropping duplicate URLs.
func mergePosts(ctx context.Context, reqMap map[network.RequestID]*HTTPRequest, winPosts []HTTPRequest) []HTTPRequest {
	var posts []HTTPRequest
	for id, r := range reqMap {
		if r.Body == "" {
			if data, err := network.GetRequestPostData(id).Do(ctx); err == nil && data != "" {
				r.Body = data
			}
		}
		posts = append(posts, *r)
	}
	for _, p := range winPosts {
		dup := false
		for i := range posts {
			if posts[i].URL == p.URL {
				dup = true
				if posts[i].Body == "" && p.Body != "" {
					posts[i].Body = p.Body
				}
				break
			}
		}
		if !dup {
			posts = append(posts, p)
		}
	}
	return posts
}

// scriptKeys returns the collected script URLs as a slice.
func scriptKeys(set map[string]struct{}) []string {
	scripts := make([]string, 0, len(set))
	for s := range set {
		scripts = append(scripts, s)
	}
	return scripts
}

// exploreField describes a single form control discovered in the page, as
// returned by the injected tagForms helper.
type exploreField struct {
	Tag         string `json:"tag"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	ID          string `json:"id"`
	Placeholder string `json:"placeholder"`
}

// exploreForm is a form and its controls, tagged in the DOM so it can be filled
// and submitted by index.
type exploreForm struct {
	Index  int            `json:"index"`
	Fields []exploreField `json:"fields"`
}

// formValues chooses a plausible value for every fillable control of a form,
// keyed by the control's name (falling back to its id) so the injected
// fillAndSubmit helper can populate the form before submitting it. Controls that
// carry no user value — hidden fields, buttons, file inputs, and checkable
// inputs (handled by the helper directly) — are skipped.
func formValues(f exploreForm) map[string]string {
	vals := make(map[string]string)
	for _, fld := range f.Fields {
		key := fld.Name
		if key == "" {
			key = fld.ID
		}
		if key == "" {
			continue
		}
		switch strings.ToLower(fld.Type) {
		case "hidden", "submit", "button", "reset", "image", "file", "checkbox", "radio":
			continue
		}
		vals[key] = plausibleFormValue(fld.Type, fld.Name, fld.ID, fld.Placeholder)
	}
	return vals
}

// plausibleFormValue returns a value likely to satisfy a form control's
// client-side validation so the form actually submits and the state behind it is
// revealed. It keys first off the HTML input type (email, number, date, …) and
// then, for free-text controls, off hints in the field's name, id and
// placeholder (an "email" text field still gets an address, a "phone" field a
// number). It falls back to a generic non-empty token so required text fields
// are never left blank.
func plausibleFormValue(fieldType, name, id, placeholder string) string {
	switch strings.ToLower(strings.TrimSpace(fieldType)) {
	case "email":
		return "test@example.com"
	case "password":
		return "Password123!"
	case "number", "range":
		return "42"
	case "tel":
		return "5555550123"
	case "url":
		return "https://example.com"
	case "date":
		return "2024-01-01"
	case "datetime-local":
		return "2024-01-01T12:00"
	case "month":
		return "2024-01"
	case "week":
		return "2024-W01"
	case "time":
		return "12:00"
	case "color":
		return "#3366cc"
	case "search":
		return "test"
	}

	hint := strings.ToLower(name + " " + id + " " + placeholder)
	switch {
	case containsAny(hint, "email", "e-mail"):
		return "test@example.com"
	case containsAny(hint, "password", "passwd", "pwd"):
		return "Password123!"
	case containsAny(hint, "phone", "tel", "mobile"):
		return "5555550123"
	case containsAny(hint, "zip", "postal"):
		return "12345"
	case containsAny(hint, "url", "website", "http"):
		return "https://example.com"
	case containsAny(hint, "first name", "firstname", "fname"):
		return "Test"
	case containsAny(hint, "last name", "lastname", "lname", "surname"):
		return "User"
	case containsAny(hint, "username", "user name", "login", "handle"):
		return "testuser"
	case containsAny(hint, "name"):
		return "Test User"
	case containsAny(hint, "city", "town"):
		return "Springfield"
	case containsAny(hint, "state", "province"):
		return "CA"
	case containsAny(hint, "country"):
		return "US"
	case containsAny(hint, "company", "organization", "organisation"):
		return "Example Inc"
	case containsAny(hint, "age"):
		return "30"
	case containsAny(hint, "amount", "price", "qty", "quantity", "number"):
		return "1"
	case containsAny(hint, "date", "dob", "birthday"):
		return "2024-01-01"
	case containsAny(hint, "message", "comment", "description", "bio", "about"):
		return "test message"
	case containsAny(hint, "search", "query", "keyword"):
		return "test"
	default:
		return "test"
	}
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// interactionScript is injected after navigation. It hooks fetch/XHR and form
// submissions so request-bearing calls made from JavaScript are captured with
// their bodies, analyses the page's forms, and installs the __jsm helpers used
// to drive interaction (tagging, clicking and form filling) from Go. It is
// idempotent: the hooks are installed once per document (guarded by
// __jsmHooked) and the captured-posts array is preserved across re-injection, so
// it can be re-run after each interaction — including after a navigation, where
// a fresh document needs the hooks re-installed.
const interactionScript = `
(function() {
	window.__interceptedPOSTs = window.__interceptedPOSTs || [];
	window.__formFields = window.__formFields || {};

	function stringifyBody(body) {
		if (!body) return '';
		if (typeof body === 'string') return body;
		if (body instanceof FormData) {
			var pairs = [];
			for (var pair of body) { pairs.push(pair[0] + '=' + encodeURIComponent(pair[1])); }
			return pairs.join('&');
		}
		if (body instanceof URLSearchParams) { return body.toString(); }
		try { return JSON.stringify(body); } catch (e) { return String(body); }
	}

	function recordPost(url, body) {
		try {
			window.__interceptedPOSTs.push({ URL: new URL(url, window.location.href).href, Body: body || '' });
		} catch (e) {}
	}

	if (!window.__jsmHooked) {
		window.__jsmHooked = true;

		var originalFetch = window.fetch;
		window.fetch = function() {
			var args = arguments;
			var url = args[0];
			var options = args[1] || {};
			if (options.method && ['POST','PUT','PATCH'].indexOf(options.method.toUpperCase()) !== -1) {
				recordPost(url, stringifyBody(options.body));
			}
			return originalFetch.apply(this, args);
		};

		var XHR = XMLHttpRequest.prototype;
		var originalOpen = XHR.open;
		var originalSend = XHR.send;
		XHR.open = function(method, url) {
			this._method = method;
			this._url = url;
			return originalOpen.apply(this, arguments);
		};
		XHR.send = function(data) {
			if (this._method && ['POST','PUT','PATCH'].indexOf(this._method.toUpperCase()) !== -1) {
				recordPost(this._url, stringifyBody(data));
			}
			return originalSend.apply(this, arguments);
		};

		document.addEventListener('submit', function(e) {
			var form = e.target;
			if (form && form.tagName === 'FORM') {
				try {
					var fd = new FormData(form);
					recordPost(form.action || window.location.href, new URLSearchParams(fd).toString());
				} catch (ex) {}
			}
		}, true);

		function analyzeForms() {
			var forms = document.querySelectorAll('form');
			forms.forEach(function(form, idx) {
				var key = form.action || 'form_' + idx;
				window.__formFields[key] = {};
				form.querySelectorAll('input, select, textarea').forEach(function(input) {
					var name = input.name || input.id || input.type;
					if (name) {
						window.__formFields[key][name] = {
							type: input.type || 'text', name: input.name, id: input.id,
							placeholder: input.placeholder, required: input.required, value: input.value || ''
						};
					}
				});
			});
		}
		analyzeForms();
		try {
			var observer = new MutationObserver(analyzeForms);
			if (document.body) { observer.observe(document.body, { childList: true, subtree: true }); }
		} catch (e) {}
	}

	// Interaction helpers, (re)defined on every injection so they survive the DOM
	// rebuild a client-side route change performs.
	window.__jsm = {
		// tagClickables tags and counts client-side navigation candidates: buttons
		// (except form submit buttons, driven via forms) and in-page or javascript:
		// anchors. Anchors to real URLs are excluded — the crawl already follows the
		// link graph — so this focuses on surface hidden behind event handlers.
		tagClickables: function() {
			// Clear stale handles so a leftover index from a prior state cannot
			// shadow a freshly-tagged element of the same index (see tagRouteLinks).
			Array.prototype.slice.call(document.querySelectorAll('[data-jsm-click]')).forEach(function(el) { el.removeAttribute('data-jsm-click'); });
			var sel = 'button, [role=button], [onclick], a[href^="#"], a[href^="javascript:"], a[href=""], [ng-click], [data-toggle], [data-target]';
			var nodes = Array.prototype.slice.call(document.querySelectorAll(sel));
			nodes = nodes.filter(function(el) {
				if (el.tagName === 'A') {
					var href = el.getAttribute('href') || '';
					return href === '' || href.charAt(0) === '#' || href.toLowerCase().indexOf('javascript:') === 0;
				}
				if (el.tagName === 'BUTTON') {
					return (el.getAttribute('type') || '').toLowerCase() !== 'submit';
				}
				return true;
			});
			nodes.forEach(function(el, i) { el.setAttribute('data-jsm-click', i); });
			return nodes.length;
		},
		// tagForms tags every form and returns a descriptor of its controls so Go
		// can choose plausible values to fill them with.
		tagForms: function() {
			var forms = Array.prototype.slice.call(document.querySelectorAll('form'));
			return forms.map(function(f, i) {
				f.setAttribute('data-jsm-form', i);
				var fields = [];
				f.querySelectorAll('input, select, textarea').forEach(function(inp) {
					fields.push({
						tag: inp.tagName.toLowerCase(), type: inp.type || 'text',
						name: inp.name || '', id: inp.id || '', placeholder: inp.placeholder || ''
					});
				});
				return { index: i, fields: fields };
			});
		},
		click: function(i) {
			var el = document.querySelector('[data-jsm-click="' + i + '"]');
			if (!el) return false;
			try { el.click(); return true; } catch (e) { return false; }
		},
		// tagRouteLinks tags same-origin <a href> route links — the client-side
		// routes an SPA renders in place. tagClickables deliberately skips these
		// (the crawl follows the real link graph), but when every route serves an
		// identical HTML shell the crawl dedups them before rendering, so their
		// client-rendered DOM — and any secret it injects at runtime — is only
		// reachable by navigating here. Cross-origin, hash and javascript:/mailto:/
		// tel: links are excluded, as is the current route. Returns the tagged
		// route paths in order; the array index is the data-jsm-route handle.
		tagRouteLinks: function() {
			// Clear stale handles first. Because the current route is excluded from
			// tagging, an excluded link would otherwise keep a data-jsm-route index
			// from a previous tagging and, being first in document order, shadow a
			// freshly-tagged link that reused the same index — so clickRoute would
			// hit the wrong anchor.
			Array.prototype.slice.call(document.querySelectorAll('[data-jsm-route]')).forEach(function(el) { el.removeAttribute('data-jsm-route'); });
			var out = [];
			var cur = location.pathname + location.search;
			var anchors = Array.prototype.slice.call(document.querySelectorAll('a[href]'));
			for (var i = 0; i < anchors.length; i++) {
				var a = anchors[i];
				var raw = a.getAttribute('href') || '';
				if (!raw || raw.charAt(0) === '#') continue;
				var lower = raw.toLowerCase();
				if (lower.indexOf('javascript:') === 0 || lower.indexOf('mailto:') === 0 || lower.indexOf('tel:') === 0) continue;
				var u;
				try { u = new URL(a.href, location.href); } catch (e) { continue; }
				if (u.origin !== location.origin) continue;
				var key = u.pathname + u.search;
				if (key === cur || out.indexOf(key) !== -1) continue;
				a.setAttribute('data-jsm-route', out.length);
				out.push(key);
			}
			return out;
		},
		clickRoute: function(i) {
			var el = document.querySelector('[data-jsm-route="' + i + '"]');
			if (!el) return false;
			try { el.click(); return true; } catch (e) { return false; }
		},
		// fillAndSubmit populates form i from values (keyed by control name/id),
		// checks checkable inputs, selects the first real option of any <select>,
		// dispatches input/change so frameworks observe the change, then submits.
		fillAndSubmit: function(i, values) {
			var f = document.querySelector('[data-jsm-form="' + i + '"]');
			if (!f) return false;
			values = values || {};
			f.querySelectorAll('input, select, textarea').forEach(function(inp) {
				var type = (inp.type || 'text').toLowerCase();
				if (type === 'checkbox' || type === 'radio') { inp.checked = true; return; }
				if (['hidden','submit','button','reset','image','file'].indexOf(type) !== -1) { return; }
				if (inp.tagName.toLowerCase() === 'select') {
					var opt = Array.prototype.slice.call(inp.options).filter(function(o){ return o.value; })[0];
					if (opt) { inp.value = opt.value; }
				} else {
					var key = inp.name || inp.id;
					if (key && values[key] !== undefined) { inp.value = values[key]; }
					else if (!inp.value) { inp.value = 'test'; }
				}
				try {
					inp.dispatchEvent(new Event('input', { bubbles: true }));
					inp.dispatchEvent(new Event('change', { bubbles: true }));
				} catch (e) {}
			});
			try {
				if (typeof f.requestSubmit === 'function') { f.requestSubmit(); } else { f.submit(); }
				return true;
			} catch (e) { return false; }
		}
	};
})();
`
