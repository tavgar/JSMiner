package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
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

	// goproxy serves each proxied connection in its own goroutine, so this
	// OnResponse handler runs concurrently for simultaneous requests. The Printer
	// is stateful (it tracks whether the banner was emitted) and issues several
	// writes per match, so concurrent Print calls would race on that state and
	// interleave each other's output on the shared writer. Serialize the print so
	// each result block is emitted atomically. Scanning itself is left outside the
	// lock: the Extractor is safe for concurrent read use, so responses are still
	// scanned in parallel.
	var printMu sync.Mutex

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

		// The full body above is forwarded to the client untouched; bound only the
		// slice handed to the scanner so an oversized response cannot make rule and
		// endpoint matching run over an unbounded input, matching the cap the rest
		// of the package applies to every network read.
		scanData := data
		if len(scanData) > scan.MaxResponseBodyBytes {
			scanData = scanData[:scan.MaxResponseBodyBytes]
		}

		ms, err := ext.ScanReaderWithEndpoints(resp.Request.URL.String(), bytes.NewReader(scanData))
		if err == nil {
			if endpoints {
				ms = scan.FilterEndpointMatches(ms)
			}
			if len(ms) > 0 {
				printMu.Lock()
				err := printer.Print(out, ms)
				printMu.Unlock()
				if err != nil {
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
