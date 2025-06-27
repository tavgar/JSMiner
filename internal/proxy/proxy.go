package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/tavgar/JSMiner/internal/output"
	"github.com/tavgar/JSMiner/internal/scan"
)

// Run starts an HTTP proxy server that scans all HTTP responses using the
// provided Extractor. Matches are printed live with the given Printer.
func Run(addr string, ext *scan.Extractor, printer *output.Printer, out io.Writer, endpoints bool) error {
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
				_ = printer.Print(out, ms)
			}
		}
		return resp
	})

	log.Printf("Proxy listening on %s", addr)
	return http.ListenAndServe(addr, prx)
}
