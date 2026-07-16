package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Crawl checkpointing lets a long crawl survive being killed. When a resume file
// is configured the crawl periodically writes its whole recoverable state — the
// pages visited, the URLs still queued, the matches found so far and the page
// count — to that file, and a later run with the same seed reloads it and
// continues instead of starting from zero. The file is written atomically (temp
// file + rename) so a crash mid-write can never leave a truncated, unreadable
// checkpoint. On clean completion the crawl removes the file, since there is
// nothing left to resume.

// crawlCheckpointVersion is bumped when the on-disk format changes; a checkpoint
// written by a different version is ignored rather than misread.
const crawlCheckpointVersion = 3

// crawlCheckpointInterval is how many completed pages pass between checkpoint
// writes. Small enough that a kill loses little progress, large enough that the
// write cost stays negligible against per-page fetch/render.
const crawlCheckpointInterval = 20

// checkpointTarget is a queued page persisted in a checkpoint.
type checkpointTarget struct {
	URL           string `json:"url"`
	Depth         int    `json:"depth"`
	Permuted      bool   `json:"permuted,omitempty"`
	PassiveSource string `json:"passive_source,omitempty"`
}

type passiveCheckpointStats struct {
	Found     int `json:"found"`
	Enqueued  int `json:"enqueued"`
	Validated int `json:"validated"`
	Rejected  int `json:"rejected"`
}

// crawlCheckpoint is the serialised, resumable state of a crawl.
type crawlCheckpoint struct {
	Version      int                    `json:"version"`
	Seed         string                 `json:"seed"`
	Pages        int                    `json:"pages"`
	CrawlDelayMS int64                  `json:"crawl_delay_ms"`
	Visited      []string               `json:"visited"`
	Enqueued     []string               `json:"enqueued"`
	Frontier     []checkpointTarget     `json:"frontier"`
	Matches      []Match                `json:"matches"`
	Permuter     *permuterState         `json:"permuter,omitempty"`
	Passive      passiveCheckpointStats `json:"passive"`
}

// checkpointCompletedPages converts the live coordinator's dispatch count into
// the completed count persisted in a checkpoint. In-flight pages are placed back
// on the saved frontier, so counting them in Pages as well would consume their
// budget twice after a resume.
func checkpointCompletedPages(dispatched, inflight int) int {
	done := dispatched - inflight
	if done < 0 {
		return 0
	}
	return done
}

// writeCheckpoint serialises cp to path atomically: it writes a sibling temp file
// and renames it over path, so a reader (or a resume after a crash) never sees a
// half-written file.
func writeCheckpoint(path string, cp crawlCheckpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jsminer-crawl-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// readCheckpoint loads a checkpoint from path. It returns an error when the file
// is absent, unreadable, malformed or written by a different format version, so
// the caller can simply fall back to a fresh crawl.
func readCheckpoint(path string) (crawlCheckpoint, error) {
	var cp crawlCheckpoint
	data, err := os.ReadFile(path)
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return cp, err
	}
	if cp.Version != crawlCheckpointVersion {
		return crawlCheckpoint{}, errCheckpointVersion
	}
	return cp, nil
}

// errCheckpointVersion signals a checkpoint written by an incompatible version.
var errCheckpointVersion = &checkpointError{"incompatible checkpoint version"}

type checkpointError struct{ msg string }

func (e *checkpointError) Error() string { return e.msg }

// removeCheckpoint deletes the checkpoint file, ignoring a missing file. It is
// called on clean completion, when there is nothing left to resume.
func removeCheckpoint(path string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		vlog(1, "[crawl] could not remove checkpoint %s: %v", path, err)
	}
}

// mapKeys returns the keys of a string-set map, for persisting the enqueued set.
func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
