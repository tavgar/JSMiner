package scan

import (
	"context"
	"strings"
	"time"

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
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()

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
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(urlStr),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(5*time.Second),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
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
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()

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
			if e.Request != nil && e.Request.Method == "POST" {
				reqMap[e.RequestID] = &HTTPRequest{URL: e.Request.URL}
			}
		}
	})

	var html string
	err := chromedp.Run(ctx,
		network.Enable().WithMaxPostDataSize(64*1024),
		chromedp.Navigate(urlStr),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(5*time.Second),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	var posts []HTTPRequest
	for id, r := range reqMap {
		if data, err := network.GetRequestPostData(id).Do(ctx); err == nil {
			r.Body = data
		}
		posts = append(posts, *r)
	}

	scripts := make([]string, 0, len(scriptSet))
	for s := range scriptSet {
		scripts = append(scripts, s)
	}
	return []byte(html), scripts, posts, nil
}
