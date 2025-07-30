package scan

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

// extraHeaders holds additional headers specified by the user via CLI flags.
// It is modified through SetExtraHeaders and read by request helper functions.
var extraHeaders = make(http.Header)

// SetExtraHeaders replaces the global extra headers used for all outgoing
// HTTP requests. It makes a copy of the provided header map.
func SetExtraHeaders(h http.Header) {
	extraHeaders = make(http.Header)
	for k, vals := range h {
		for _, v := range vals {
			extraHeaders.Add(k, v)
		}
	}
}

// applyHeaders sets the default User-Agent and any extra headers on req.
func applyHeaders(req *http.Request) {
	ua := defaultUserAgent
	if vals := extraHeaders.Values("User-Agent"); len(vals) > 0 {
		ua = vals[len(vals)-1]
	}
	req.Header.Set("User-Agent", ua)
	for k, vals := range extraHeaders {
		if strings.EqualFold(k, "User-Agent") {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
}

// FetchURL retrieves the content at url with timeouts and limited redirects
func FetchURL(url string) (io.ReadCloser, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if SkipTLSVerification {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
	client := http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
