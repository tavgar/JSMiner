package scan

import (
	"context"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

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
