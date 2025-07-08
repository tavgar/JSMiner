package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	printer := output.NewPrinter("json", false, true, "test")

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
