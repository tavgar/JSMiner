package scan

import (
	"io"
	"sync"
)

// ScanDir scans all supported files under root directory using workers
// to limit concurrency.
func (e *Extractor) ScanDir(root string, workers int) ([]Match, error) {
	files, err := WalkDir(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	if workers <= 0 {
		workers = 1
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	matchesCh := make(chan []Match, len(files))
	errCh := make(chan error, len(files))

	for name, r := range files {
		sem <- struct{}{}
		wg.Add(1)
		go func(n string, rc io.ReadCloser) {
			defer wg.Done()
			defer func() { <-sem }()
			defer rc.Close()

			ms, err := e.ScanReader(n, rc)
			if err != nil {
				errCh <- err
				return
			}
			if len(ms) > 0 {
				matchesCh <- ms
			}
		}(name, r)
	}

	go func() {
		wg.Wait()
		close(matchesCh)
		close(errCh)
	}()

	var matches []Match
	for m := range matchesCh {
		matches = append(matches, m...)
	}

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}

	return matches, firstErr
}
