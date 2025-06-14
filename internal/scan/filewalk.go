package scan

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var exts = []string{".html", ".js", ".ts", ".jsx", ".wasm", ".zip", ".jar"}

// WalkDir walks directory and returns list of readers with their filenames
func WalkDir(root string) (map[string]io.ReadCloser, error) {
	files := make(map[string]io.ReadCloser)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if matchExt(path) {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".zip" || ext == ".jar" {
				zr, err := zip.OpenReader(path)
				if err != nil {
					return err
				}
				defer zr.Close()
				for _, zf := range zr.File {
					if matchExt(zf.Name) {
						rc, err := zf.Open()
						if err != nil {
							return err
						}
						data, err := io.ReadAll(rc)
						rc.Close()
						if err != nil {
							return err
						}
						name := path + ":" + zf.Name
						files[name] = io.NopCloser(bytes.NewReader(data))
					}
				}
			} else {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				files[path] = f
			}
		}
		return nil
	})
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		return nil, err
	}
	return files, nil
}

func matchExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range exts {
		if ext == e {
			return true
		}
	}
	return false
}
