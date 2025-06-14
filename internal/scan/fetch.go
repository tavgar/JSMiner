package scan

import (
	"io"
	"net/http"
	"time"
)

// FetchURL retrieves the content at url with timeouts and limited redirects
func FetchURL(url string) (io.Reader, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
