package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tavgar/JSMiner/internal/output"
	"github.com/tavgar/JSMiner/internal/scan"
)

func TestProxyScansResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "token eyJabc.def.ghi")
	}))
	defer backend.Close()

	e := scan.NewExtractor(false, false)
	buf := &bytes.Buffer{}
	printer := output.NewPrinter("json", false, true, false, "test")

	// Choose an available port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, addr, e, printer, buf, false)
	}()
	// give server time to start
	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("client get failed: %v", err)
	}
	resp.Body.Close()

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("proxy run error: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("jwt")) {
		t.Fatalf("expected jwt match in output, got %s", buf.String())
	}
}

// TestProxyConcurrentResponses drives many requests through the proxy at once so
// the OnResponse handler runs on several goroutines concurrently. goproxy serves
// each connection in its own goroutine, and the Printer is stateful and writes to
// a shared buffer, so without serialization this races on printer state and the
// output writer. Run under -race to catch a regression.
func TestProxyConcurrentResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "token eyJabc.def.ghi")
	}))
	defer backend.Close()

	e := scan.NewExtractor(false, false)
	buf := &bytes.Buffer{}
	printer := output.NewPrinter("json", true, true, false, "test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, addr, e, printer, buf, false)
	}()
	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + addr)

	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A fresh transport per goroutine forces distinct proxy connections, so
			// the responses are handled concurrently rather than serialized on one
			// keep-alive connection.
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			resp, err := client.Get(backend.URL)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("proxy run error: %v", err)
	}
}
