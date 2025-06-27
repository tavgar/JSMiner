package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/tavgar/JSMiner/internal/output"
	"github.com/tavgar/JSMiner/internal/scan"
)

// Run starts an HTTP proxy server that scans all HTTP responses using the
// provided Extractor. Matches are printed live with the given Printer.
func Run(ctx context.Context, addr string, ext *scan.Extractor, printer *output.Printer, out io.Writer, endpoints bool) error {
	prx := goproxy.NewProxyHttpServer()
	prx.Verbose = false
	// Enable MITM for HTTPS so response bodies can be inspected.
	prx.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	prx.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || resp.Body == nil || resp.Request == nil {
			return resp
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewBuffer(data))

		ms, err := ext.ScanReaderWithEndpoints(resp.Request.URL.String(), bytes.NewReader(data))
		if err == nil {
			if endpoints {
				ms = scan.FilterEndpointMatches(ms)
			}
			if len(ms) > 0 {
				if err := printer.Print(out, ms); err != nil {
					log.Printf("printer error: %v", err)
				}
			}
		}
		return resp
	})

	srv := &http.Server{Handler: prx}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("Proxy listening on %s", ln.Addr().String())

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
