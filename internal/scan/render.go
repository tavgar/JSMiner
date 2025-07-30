package scan

import (
	"context"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// HTTPRequest represents a captured HTTP request.
type HTTPRequest struct {
	URL  string
	Body string
}

// RenderURL loads the page at urlStr in headless Chrome and returns the
// rendered HTML along with JavaScript URLs fetched during the page load.
func RenderURL(urlStr string) ([]byte, []string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if SkipTLSVerification {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, RenderTimeout)
	defer cancelTimeout()

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

	scriptSet := make(map[string]struct{})
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if e, ok := ev.(*network.EventResponseReceived); ok {
			u := e.Response.URL
			if strings.HasSuffix(strings.ToLower(u), ".js") ||
				strings.Contains(e.Response.MimeType, "javascript") {
				scriptSet[u] = struct{}{}
			}
		}
	})

	var html string
	actions := []chromedp.Action{network.Enable()}
	if len(headers) > 0 {
		actions = append(actions,
			network.SetExtraHTTPHeaders(network.Headers(headers)),
			emulation.SetUserAgentOverride(headers["User-Agent"].(string)),
		)
	}
	actions = append(actions,
		chromedp.Navigate(urlStr),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(RenderSleepDuration),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	err := chromedp.Run(ctx, actions...)
	if err != nil {
		return nil, nil, err
	}

	scripts := make([]string, 0, len(scriptSet))
	for s := range scriptSet {
		scripts = append(scripts, s)
	}
	return []byte(html), scripts, nil
}

// RenderURLWithRequests loads the page and captures POST requests made during
// rendering. It returns the rendered HTML, JavaScript URLs and POST requests.
func RenderURLWithRequests(urlStr string) ([]byte, []string, []HTTPRequest, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if SkipTLSVerification {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, RenderTimeout)
	defer cancelTimeout()

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

	scriptSet := make(map[string]struct{})
	reqMap := make(map[network.RequestID]*HTTPRequest)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			u := e.Response.URL
			if strings.HasSuffix(strings.ToLower(u), ".js") ||
				strings.Contains(e.Response.MimeType, "javascript") {
				scriptSet[u] = struct{}{}
			}
		case *network.EventRequestWillBeSent:
			if e.Request != nil && (e.Request.Method == "POST" || e.Request.Method == "PUT" || e.Request.Method == "PATCH") {
				req := &HTTPRequest{URL: e.Request.URL}
				// Try to get POST data immediately
				if e.Request.HasPostData {
					// PostData will be retrieved later
					req.Body = ""
				}
				reqMap[e.RequestID] = req
			}
		case *network.EventRequestWillBeSentExtraInfo:
			// Capture additional POST data that might not be in RequestWillBeSent
			if req, ok := reqMap[e.RequestID]; ok && req.Body == "" {
				// Headers might contain form data info
				if contentType, ok := e.Headers["Content-Type"]; ok {
					if ct, ok := contentType.(string); ok {
						if strings.Contains(ct, "application/x-www-form-urlencoded") ||
							strings.Contains(ct, "multipart/form-data") {
							// Mark that this is likely a form submission
							req.Body = "[Form data captured via headers]"
						}
					}
				}
			}
		}
	})

	// JavaScript to inject for intercepting fetch/XHR and analyzing forms
	interceptScript := `
	(function() {
		window.__interceptedPOSTs = [];
		window.__formFields = {};
		
		// Helper to stringify body data
		function stringifyBody(body) {
			if (!body) return '';
			if (typeof body === 'string') return body;
			if (body instanceof FormData) {
				const pairs = [];
				for (const [key, value] of body) {
					pairs.push(key + '=' + encodeURIComponent(value));
				}
				return pairs.join('&');
			}
			if (body instanceof URLSearchParams) {
				return body.toString();
			}
			try {
				return JSON.stringify(body);
			} catch (e) {
				return String(body);
			}
		}
		
		// Intercept fetch
		const originalFetch = window.fetch;
		window.fetch = function(...args) {
			const [url, options = {}] = args;
			if (options.method && ['POST', 'PUT', 'PATCH'].includes(options.method.toUpperCase())) {
				const bodyStr = stringifyBody(options.body);
				window.__interceptedPOSTs.push({
					url: new URL(url, window.location.href).href,
					body: bodyStr
				});
			}
			return originalFetch.apply(this, args);
		};
		
		// Intercept XMLHttpRequest
		const XHR = XMLHttpRequest.prototype;
		const originalOpen = XHR.open;
		const originalSend = XHR.send;
		
		XHR.open = function(method, url, ...args) {
			this._method = method;
			this._url = url;
			return originalOpen.apply(this, [method, url, ...args]);
		};
		
		XHR.send = function(data) {
			if (this._method && ['POST', 'PUT', 'PATCH'].includes(this._method.toUpperCase())) {
				const bodyStr = stringifyBody(data);
				window.__interceptedPOSTs.push({
					url: new URL(this._url, window.location.href).href,
					body: bodyStr
				});
			}
			return originalSend.apply(this, arguments);
		};
		
		// Analyze forms on the page
		function analyzeForms() {
			const forms = document.querySelectorAll('form');
			forms.forEach((form, idx) => {
				const formKey = form.action || 'form_' + idx;
				window.__formFields[formKey] = {};
				
				const inputs = form.querySelectorAll('input, select, textarea');
				inputs.forEach(input => {
					const name = input.name || input.id || input.type;
					if (name) {
						window.__formFields[formKey][name] = {
							type: input.type || 'text',
							name: input.name,
							id: input.id,
							placeholder: input.placeholder,
							required: input.required,
							value: input.value || ''
						};
					}
				});
			});
		}
		
		// Initial analysis
		analyzeForms();
		
		// Re-analyze when DOM changes
		const observer = new MutationObserver(analyzeForms);
		observer.observe(document.body, { childList: true, subtree: true });
		
		// Intercept form submissions
		document.addEventListener('submit', function(e) {
			const form = e.target;
			if (form.tagName === 'FORM') {
				const formData = new FormData(form);
				const params = {};
				for (const [key, value] of formData) {
					params[key] = value;
				}
				
				const body = new URLSearchParams(formData).toString();
				window.__interceptedPOSTs.push({
					url: new URL(form.action || window.location.href, window.location.href).href,
					body: body
				});
			}
		}, true);
	})();
	`

	var html string
	var interceptedPosts []HTTPRequest
	var formFields map[string]interface{}

	actions := []chromedp.Action{network.Enable().WithMaxPostDataSize(MaxPostDataSize)}
	if len(headers) > 0 {
		actions = append(actions,
			network.SetExtraHTTPHeaders(network.Headers(headers)),
			emulation.SetUserAgentOverride(headers["User-Agent"].(string)),
		)
	}
	actions = append(actions,
		chromedp.Navigate(urlStr),
		chromedp.Evaluate(interceptScript, nil),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(RenderSleepDuration),
		chromedp.Evaluate(`window.__interceptedPOSTs || []`, &interceptedPosts),
		chromedp.Evaluate(`window.__formFields || {}`, &formFields),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	err := chromedp.Run(ctx, actions...)
	if err != nil {
		return nil, nil, nil, err
	}

	var posts []HTTPRequest
	for id, r := range reqMap {
		// Try to get POST data if we don't have it yet
		if r.Body == "" {
			if data, err := network.GetRequestPostData(id).Do(ctx); err == nil && data != "" {
				r.Body = data
			}
		}
		posts = append(posts, *r)
	}

	// Add intercepted posts from JavaScript
	for _, p := range interceptedPosts {
		// Check if we already have this request (avoid duplicates)
		duplicate := false
		for _, existing := range posts {
			if existing.URL == p.URL {
				duplicate = true
				// If existing has no body but intercepted does, update it
				if existing.Body == "" && p.Body != "" {
					existing.Body = p.Body
				}
				break
			}
		}
		if !duplicate {
			posts = append(posts, p)
		}
	}

	// For POST endpoints without body, try to infer parameters from forms
	for i := range posts {
		if posts[i].Body == "" || posts[i].Body == "[Form data captured via headers]" {
			// Try to match URL with form actions
			for formAction, fields := range formFields {
				if strings.Contains(posts[i].URL, formAction) || formAction == "form_0" {
					// Build parameter list from form fields
					params := []string{}
					if fieldsMap, ok := fields.(map[string]interface{}); ok {
						for fieldName, fieldInfo := range fieldsMap {
							if info, ok := fieldInfo.(map[string]interface{}); ok {
								fieldType := "text"
								if t, ok := info["type"].(string); ok {
									fieldType = t
								}
								// Skip hidden submit buttons
								if fieldType != "submit" && fieldType != "button" {
									params = append(params, fieldName+"=["+fieldType+"]")
								}
							}
						}
					}
					if len(params) > 0 {
						posts[i].Body = "Form fields: " + strings.Join(params, "&")
					}
					break
				}
			}
		}
	}

	scripts := make([]string, 0, len(scriptSet))
	for s := range scriptSet {
		scripts = append(scripts, s)
	}
	return []byte(html), scripts, posts, nil
}
